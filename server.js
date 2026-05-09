require('dotenv').config();

const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('./db');

const fetch = (...args) =>
    import('node-fetch').then(({ default: fetch }) => fetch(...args));

const app = express();

app.use(helmet());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES = process.env.JWT_EXPIRES || '7d';

if (!JWT_SECRET) {
    console.error('JWT_SECRET is missing in .env');
    process.exit(1);
}

app.use(cors({
    origin: process.env.CLIENT_URL || '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
}));

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];

    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

function adminMiddleware(req, res, next) {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied. Admins only.' });
    }

    next();
}

function makeFallbackReply(message, hotels) {
    const text = message.toLowerCase();

    if (text.includes('привет') || text.includes('здравствуй') || text.includes('hello')) {
        return 'Здравствуйте! Я AI-ассистент StayFinder. Я помогу подобрать отель, объяснить бронирование, отзывы и работу профиля.';
    }

    if (text.includes('дешев') || text.includes('бюджет') || text.includes('недорог')) {
        if (!hotels.length) {
            return 'Пока в базе нет отелей.';
        }

        return 'Самые недорогие варианты:\n\n' + hotels.slice(0, 3).map(h =>
            `• ${h.name} — ${h.city}, ${h.price} ₸ за ночь`
        ).join('\n');
    }

    if (text.includes('брон') || text.includes('забронировать')) {
        return 'Чтобы забронировать номер: выберите отель на главной странице, нажмите Details, укажите даты заезда и выезда, затем нажмите Book Now. Для бронирования нужно войти в аккаунт.';
    }

    if (text.includes('отзыв') || text.includes('рейтинг')) {
        return 'Отзывы можно оставить на странице конкретного отеля. Откройте отель, выберите оценку от 1 до 5, напишите комментарий и отправьте отзыв.';
    }

    if (text.includes('профиль') || text.includes('мои бронирования')) {
        return 'Ваши бронирования находятся в разделе Profile. Там можно посмотреть активные бронирования и информацию о пользователе.';
    }

    const cityHotel = hotels.find(h => text.includes(String(h.city).toLowerCase()));

    if (cityHotel) {
        const found = hotels.filter(h => text.includes(String(h.city).toLowerCase()));

        return 'Я нашёл отели по вашему городу:\n\n' + found.map(h =>
            `• ${h.name} — ${h.city}, ${h.price} ₸ за ночь`
        ).join('\n');
    }

    if (text.includes('отель') || text.includes('hotel')) {
        if (!hotels.length) {
            return 'Пока в базе нет отелей.';
        }

        return 'Вот несколько отелей из базы:\n\n' + hotels.slice(0, 5).map(h =>
            `• ${h.name} — ${h.city}, ${h.price} ₸ за ночь`
        ).join('\n');
    }

    return 'Я могу помочь подобрать отель, найти дешевые варианты, объяснить бронирование, отзывы и профиль. Например, напишите: "посоветуй дешевый отель" или "как забронировать номер?".';
}

app.get('/', (req, res) => {
    res.json({ message: 'Hotel Booking API is running' });
});

/* REGISTER */
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Заполните все поля' });
    }

    if (username.trim().length < 3) {
        return res.status(400).json({ error: 'Имя должно быть минимум 3 символа' });
    }

    if (!isValidEmail(email)) {
        return res.status(400).json({ error: 'Некорректный email' });
    }

    if (password.length < 6) {
        return res.status(400).json({ error: 'Пароль должен быть минимум 6 символов' });
    }

    try {
        const existingUser = await pool.query(
            'SELECT id FROM users WHERE email = $1',
            [email.toLowerCase()]
        );

        if (existingUser.rows.length > 0) {
            return res.status(409).json({ error: 'Пользователь с таким email уже существует' });
        }

        const hash = await bcrypt.hash(password, 12);

        const result = await pool.query(
            `INSERT INTO users (username, email, password)
             VALUES ($1, $2, $3)
             RETURNING id, username, email, role, created_at`,
            [username.trim(), email.toLowerCase(), hash]
        );

        res.status(201).json({
            message: 'Аккаунт создан',
            user: result.rows[0]
        });

    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

/* LOGIN */
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Заполните все поля' });
    }

    try {
        const result = await pool.query(
            'SELECT id, username, email, password, role FROM users WHERE email = $1',
            [email.toLowerCase()]
        );

        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }

        const isPasswordCorrect = await bcrypt.compare(password, user.password);

        if (!isPasswordCorrect) {
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }

        const token = jwt.sign(
            {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role
            },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES }
        );

        res.json({
            token,
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role
        });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

/* AI CHAT WITH GEMINI + FALLBACK */
app.post('/api/ai-chat', async (req, res) => {
    const { message } = req.body;

    if (!message || !message.trim()) {
        return res.status(400).json({ error: 'Message is required' });
    }

    try {
        const hotelsResult = await pool.query(
            `SELECT id, name, city, price, description, rooms_total
             FROM hotels
             ORDER BY price ASC
             LIMIT 10`
        );

        const hotels = hotelsResult.rows;

        const hotelsText = hotels.map(h =>
            `${h.name} — город ${h.city}, цена ${h.price} ₸ за ночь. ${h.description || ''}`
        ).join('\n');

        if (!process.env.GEMINI_API_KEY) {
            return res.json({
                reply: makeFallbackReply(message, hotels)
            });
        }

        try {
            const response = await fetch(
                `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${process.env.GEMINI_API_KEY}`,
                {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        contents: [
                            {
                                parts: [
                                    {
                                        text:
`Ты AI-ассистент сайта StayFinder.

Ты помогаешь пользователям:
- выбирать отели;
- искать дешевые варианты;
- объяснять бронирование;
- рассказывать про отзывы;
- помогать с профилем.

Вот отели из базы данных сайта:
${hotelsText || 'Пока отелей в базе нет.'}

Отвечай на русском языке, дружелюбно, кратко и полезно.
Если пользователь спрашивает про отели, используй данные из базы.
Если данных не хватает, честно скажи, что информации нет.

Сообщение пользователя:
${message}`
                                    }
                                ]
                            }
                        ],
                        generationConfig: {
                            temperature: 0.7,
                            maxOutputTokens: 350
                        }
                    })
                }
            );

            const data = await response.json();

            const reply = data.candidates?.[0]?.content?.parts?.[0]?.text;

            if (!response.ok || !reply) {
                console.log('GEMINI FALLBACK:', data);

                return res.json({
                    reply: makeFallbackReply(message, hotels)
                });
            }

            return res.json({ reply });

        } catch (aiErr) {
            console.error('GEMINI ERROR:', aiErr);

            return res.json({
                reply: makeFallbackReply(message, hotels)
            });
        }

    } catch (err) {
        console.error('AI CHAT DB ERROR:', err);

        res.json({
            reply: 'Сейчас ассистент временно не может получить данные из базы, но я могу подсказать: выберите отель на главной странице, откройте Details и оформите бронирование через Book Now.'
        });
    }
});

/* DB TEST */
app.get('/db-test', async (req, res) => {
    try {
        const result = await pool.query('SELECT NOW()');
        res.json({
            success: true,
            time: result.rows[0].now
        });
    } catch (err) {
        console.error('DB TEST ERROR:', err);
        res.status(500).json({
            success: false,
            message: err.message,
            code: err.code
        });
    }
});

/* HOTELS */
app.get('/hotels', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM hotels ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        console.error('Hotels error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/hotels', authMiddleware, adminMiddleware, async (req, res) => {
    const { name, city, price, description, image_url, rooms_total } = req.body;

    if (!name || !city || !price) {
        return res.status(400).json({ error: 'Название, город и цена обязательны' });
    }

    if (Number(price) <= 0) {
        return res.status(400).json({ error: 'Цена должна быть больше 0' });
    }

    try {
        const result = await pool.query(
            `INSERT INTO hotels (name, city, price, description, image_url, rooms_total)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING *`,
            [
                name.trim(),
                city.trim(),
                Number(price),
                description || '',
                image_url || '',
                Number(rooms_total) || 1
            ]
        );

        res.status(201).json(result.rows[0]);

    } catch (err) {
        console.error('Create hotel error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.delete('/hotels/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            'DELETE FROM hotels WHERE id = $1 RETURNING *',
            [req.params.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Hotel not found' });
        }

        res.json({ message: 'Hotel deleted' });

    } catch (err) {
        console.error('Delete hotel error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

/* BOOKINGS */
app.post('/bookings', authMiddleware, async (req, res) => {
    const { hotel_id, check_in, check_out } = req.body;

    if (!hotel_id || !check_in || !check_out) {
        return res.status(400).json({ error: 'Missing booking data' });
    }

    if (new Date(check_in) >= new Date(check_out)) {
        return res.status(400).json({ error: 'Invalid booking dates' });
    }

    try {
        const hotelResult = await pool.query(
            'SELECT * FROM hotels WHERE id = $1',
            [hotel_id]
        );

        if (hotelResult.rows.length === 0) {
            return res.status(404).json({ error: 'Hotel not found' });
        }

        const hotel = hotelResult.rows[0];
        const roomsTotal = Number(hotel.rooms_total) || 1;

        const overlapResult = await pool.query(
            `SELECT COUNT(*)
             FROM bookings
             WHERE hotel_id = $1
             AND check_in < $3
             AND check_out > $2`,
            [hotel_id, check_in, check_out]
        );

        const overlaps = Number(overlapResult.rows[0].count);

        if (overlaps >= roomsTotal) {
            return res.status(400).json({
                error: 'No available rooms for selected dates'
            });
        }

        const result = await pool.query(
            `INSERT INTO bookings (user_id, hotel_id, check_in, check_out)
             VALUES ($1, $2, $3, $4)
             RETURNING *`,
            [req.user.id, hotel_id, check_in, check_out]
        );

        res.status(201).json(result.rows[0]);

    } catch (err) {
        console.error('Booking error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/my-bookings', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT
                bookings.id,
                hotels.name AS hotel_name,
                hotels.city,
                hotels.price,
                hotels.image_url,
                bookings.check_in,
                bookings.check_out,
                bookings.created_at
             FROM bookings
             JOIN hotels ON bookings.hotel_id = hotels.id
             WHERE bookings.user_id = $1
             ORDER BY bookings.created_at DESC`,
            [req.user.id]
        );

        res.json(result.rows);

    } catch (err) {
        console.error('My bookings error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.delete('/bookings/:id', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            `DELETE FROM bookings
             WHERE id = $1 AND user_id = $2
             RETURNING *`,
            [req.params.id, req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Бронирование не найдено' });
        }

        res.json({ message: 'Бронирование удалено' });

    } catch (err) {
        console.error('Delete booking error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

/* ADMIN BOOKINGS */
app.get('/admin/bookings', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT
                bookings.id,
                users.username,
                users.email,
                hotels.name AS hotel_name,
                hotels.city,
                bookings.check_in,
                bookings.check_out,
                bookings.created_at
             FROM bookings
             JOIN users ON bookings.user_id = users.id
             JOIN hotels ON bookings.hotel_id = hotels.id
             ORDER BY bookings.created_at DESC`
        );

        res.json(result.rows);

    } catch (err) {
        console.error('Admin bookings error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.delete('/admin/bookings/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            'DELETE FROM bookings WHERE id = $1 RETURNING *',
            [req.params.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Booking not found' });
        }

        res.json({ message: 'Booking cancelled' });

    } catch (err) {
        console.error('Cancel booking error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

/* HOTEL AVAILABILITY */
app.get('/hotels/:id/availability', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT check_in, check_out
             FROM bookings
             WHERE hotel_id = $1
             ORDER BY check_in`,
            [req.params.id]
        );

        res.json(result.rows);

    } catch (err) {
        console.error('Availability error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

/* HOTEL REVIEWS */
app.get('/hotels/:id/reviews', async (req, res) => {
    try {
        const reviewsResult = await pool.query(
            `SELECT
                reviews.id,
                reviews.rating,
                reviews.comment,
                reviews.created_at,
                users.username
             FROM reviews
             JOIN users ON reviews.user_id = users.id
             WHERE reviews.hotel_id = $1
             ORDER BY reviews.created_at DESC`,
            [req.params.id]
        );

        const avgResult = await pool.query(
            `SELECT
                COALESCE(ROUND(AVG(rating)::numeric, 1), 0) AS average_rating,
                COUNT(*) AS total_reviews
             FROM reviews
             WHERE hotel_id = $1`,
            [req.params.id]
        );

        res.json({
            reviews: reviewsResult.rows,
            average: Number(avgResult.rows[0].average_rating),
            total: Number(avgResult.rows[0].total_reviews)
        });

    } catch (err) {
        console.error('Get reviews error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/hotels/:id/reviews', authMiddleware, async (req, res) => {
    const rating = Number(req.body.rating);
    const comment = req.body.comment || '';

    if (!rating || rating < 1 || rating > 5) {
        return res.status(400).json({ error: 'Rating must be from 1 to 5' });
    }

    try {
        const hotel = await pool.query(
            'SELECT id FROM hotels WHERE id = $1',
            [req.params.id]
        );

        if (hotel.rows.length === 0) {
            return res.status(404).json({ error: 'Hotel not found' });
        }

        const result = await pool.query(
            `INSERT INTO reviews (user_id, hotel_id, rating, comment)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (user_id, hotel_id)
             DO UPDATE SET
                rating = EXCLUDED.rating,
                comment = EXCLUDED.comment,
                created_at = CURRENT_TIMESTAMP
             RETURNING *`,
            [req.user.id, req.params.id, rating, comment]
        );

        res.status(201).json(result.rows[0]);

    } catch (err) {
        console.error('Add review error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

/* GET ONE HOTEL */
app.get('/hotels/:id', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM hotels WHERE id = $1',
            [req.params.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Hotel not found' });
        }

        res.json(result.rows[0]);

    } catch (err) {
        console.error('Get hotel error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});