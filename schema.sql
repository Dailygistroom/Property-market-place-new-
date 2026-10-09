PRAGMA foreign_keys = ON;

-- =========================================
-- JOVA PROPERTY MARKETPLACE
-- DATABASE SCHEMA
-- =========================================

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (
        role IN ('agent', 'landlord', 'developer')
    ),
    profile_image TEXT,
    company_name TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email
ON users(email);


-- =========================================
-- AUTH SESSIONS
-- =========================================

CREATE TABLE IF NOT EXISTS auth_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_token
ON auth_sessions(token);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_user
ON auth_sessions(user_id);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry
ON auth_sessions(expires_at);


-- =========================================
-- LISTING PLANS
-- =========================================

CREATE TABLE IF NOT EXISTS listing_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    price REAL NOT NULL,
    duration_days INTEGER NOT NULL,
    max_active_listings INTEGER,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- =========================================
-- PROPERTIES
-- =========================================

CREATE TABLE IF NOT EXISTS properties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,

    listing_type TEXT NOT NULL CHECK (
        listing_type IN ('sale', 'rent', 'land', 'shortlet')
    ),

    property_type TEXT NOT NULL,

    price REAL NOT NULL,
    currency TEXT NOT NULL DEFAULT 'NGN',

    address TEXT NOT NULL,
    city TEXT NOT NULL,
    state TEXT,
    country TEXT NOT NULL DEFAULT 'Nigeria',

    latitude REAL,
    longitude REAL,

    bedrooms INTEGER DEFAULT 0,
    bathrooms INTEGER DEFAULT 0,
    toilets INTEGER DEFAULT 0,
    parking_spaces INTEGER DEFAULT 0,

    size_value REAL,
    size_unit TEXT DEFAULT 'sqm',

    furnished INTEGER NOT NULL DEFAULT 0,
    serviced INTEGER NOT NULL DEFAULT 0,

    status TEXT NOT NULL DEFAULT 'draft' CHECK (
        status IN ('draft','active','sold','rented','inactive')
    ),

    plan_type TEXT NOT NULL DEFAULT 'free' CHECK (
        plan_type IN ('free','standard','featured','premium')
    ),

    listing_expires_at TEXT,

    is_featured INTEGER NOT NULL DEFAULT 0,
    views INTEGER NOT NULL DEFAULT 0,

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_properties_user
ON properties(user_id);

CREATE INDEX IF NOT EXISTS idx_properties_status
ON properties(status);

CREATE INDEX IF NOT EXISTS idx_properties_listing_type
ON properties(listing_type);

CREATE INDEX IF NOT EXISTS idx_properties_property_type
ON properties(property_type);

CREATE INDEX IF NOT EXISTS idx_properties_city
ON properties(city);

CREATE INDEX IF NOT EXISTS idx_properties_state
ON properties(state);

CREATE INDEX IF NOT EXISTS idx_properties_price
ON properties(price);


-- =========================================
-- PROPERTY IMAGES
-- MAXIMUM 6 IMAGES PER PROPERTY
-- =========================================

CREATE TABLE IF NOT EXISTS property_images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id INTEGER NOT NULL,
    image_key TEXT NOT NULL,
    image_url TEXT,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (property_id)
        REFERENCES properties(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_property_images_property
ON property_images(property_id);

CREATE TRIGGER IF NOT EXISTS max_six_property_images
BEFORE INSERT ON property_images
WHEN (
    SELECT COUNT(*)
    FROM property_images
    WHERE property_id = NEW.property_id
) >= 6
BEGIN
    SELECT RAISE(ABORT, 'A property can have a maximum of 6 images');
END;


-- =========================================
-- PROMOTION PLANS
-- =========================================

CREATE TABLE IF NOT EXISTS promotion_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    price REAL NOT NULL,
    duration_days INTEGER NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- =========================================
-- PROPERTY PROMOTIONS
-- =========================================

CREATE TABLE IF NOT EXISTS property_promotions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id INTEGER NOT NULL,
    promotion_plan_id INTEGER NOT NULL,

    starts_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (property_id)
        REFERENCES properties(id)
        ON DELETE CASCADE,

    FOREIGN KEY (promotion_plan_id)
        REFERENCES promotion_plans(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_property_promotions_property
ON property_promotions(property_id);

CREATE INDEX IF NOT EXISTS idx_property_promotions_expiry
ON property_promotions(expires_at);


-- =========================================
-- FAVOURITES
-- =========================================

CREATE TABLE IF NOT EXISTS favourites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    property_id INTEGER NOT NULL,

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(user_id, property_id),

    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    FOREIGN KEY (property_id)
        REFERENCES properties(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_favourites_user
ON favourites(user_id);

CREATE INDEX IF NOT EXISTS idx_favourites_property
ON favourites(property_id);


-- =========================================
-- ENQUIRIES
-- =========================================

CREATE TABLE IF NOT EXISTS enquiries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id INTEGER NOT NULL,
    user_id INTEGER,

    name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT,
    message TEXT NOT NULL,

    status TEXT NOT NULL DEFAULT 'new' CHECK (
        status IN ('new','read','replied','closed')
    ),

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (property_id)
        REFERENCES properties(id)
        ON DELETE CASCADE,

    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_enquiries_property
ON enquiries(property_id);

CREATE INDEX IF NOT EXISTS idx_enquiries_user
ON enquiries(user_id);


-- =========================================
-- PAYMENTS
-- =========================================

CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    user_id INTEGER NOT NULL,
    property_id INTEGER,

    listing_plan_id INTEGER,
    promotion_plan_id INTEGER,

    reference TEXT NOT NULL UNIQUE,

    amount REAL NOT NULL,
    currency TEXT NOT NULL DEFAULT 'NGN',

    payment_type TEXT NOT NULL CHECK (
        payment_type IN ('listing','promotion')
    ),

    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending','successful','failed')
    ),

    paid_at TEXT,

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    FOREIGN KEY (property_id)
        REFERENCES properties(id)
        ON DELETE SET NULL,

    FOREIGN KEY (listing_plan_id)
        REFERENCES listing_plans(id)
        ON DELETE SET NULL,

    FOREIGN KEY (promotion_plan_id)
        REFERENCES promotion_plans(id)
        ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_payments_user
ON payments(user_id);

CREATE INDEX IF NOT EXISTS idx_payments_property
ON payments(property_id);

CREATE INDEX IF NOT EXISTS idx_payments_reference
ON payments(reference);

CREATE INDEX IF NOT EXISTS idx_payments_status
ON payments(status);


-- =========================================
-- DEFAULT LISTING PLANS
-- =========================================

INSERT OR IGNORE INTO listing_plans
(name, description, price, duration_days, max_active_listings)
VALUES
(
    'free',
    'First three active listings',
    0,
    30,
    3
),
(
    'standard',
    'Standard property listing',
    15000,
    30,
    NULL
),
(
    'featured',
    'Featured property listing',
    25000,
    30,
    NULL
),
(
    'premium',
    'Premium property listing',
    50000,
    30,
    NULL
);


-- =========================================
-- DEFAULT PROMOTION PLANS
-- =========================================

INSERT OR IGNORE INTO promotion_plans
(name, description, price, duration_days)
VALUES
(
    'boost',
    'Boost property visibility',
    10000,
    7
),
(
    'featured_promotion',
    'Featured property promotion',
    20000,
    14
),
(
    'premium_promotion',
    'Premium property promotion',
    40000,
    30
);
-- =========================================
-- JOVA MESSAGING SYSTEM
-- =========================================

CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id INTEGER NOT NULL,
    buyer_id INTEGER NOT NULL,
    advertiser_id INTEGER NOT NULL,
    last_message TEXT,
    last_message_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(property_id, buyer_id, advertiser_id),

    FOREIGN KEY (property_id)
        REFERENCES properties(id) ON DELETE CASCADE,
    FOREIGN KEY (buyer_id)
        REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (advertiser_id)
        REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_conversations_buyer
ON conversations(buyer_id);

CREATE INDEX IF NOT EXISTS idx_conversations_advertiser
ON conversations(advertiser_id);

CREATE INDEX IF NOT EXISTS idx_conversations_property
ON conversations(property_id);


-- =========================================
-- JOVA MESSAGES
-- =========================================

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (conversation_id)
        REFERENCES conversations(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id)
        REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_messages_conversation
ON messages(conversation_id, created_at);

CREATE INDEX IF NOT EXISTS idx_messages_unread
ON messages(conversation_id, is_read);


-- =========================================
-- JOVA NOTIFICATIONS
-- =========================================

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    link TEXT,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_notifications_user
ON notifications(user_id, created_at);

CREATE INDEX IF NOT EXISTS idx_notifications_unread
ON notifications(user_id, is_read);
