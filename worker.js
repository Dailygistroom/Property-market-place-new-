const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Key",
  "Access-Control-Max-Age": "86400"
};

const MAX_PHOTOS = 6;
const SESSION_DAYS = 30;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...CORS_HEADERS,
      ...extraHeaders
    }
  });
}

function error(message, status = 400, extra = {}) {
  return json({
    success: false,
    error: message,
    ...extra
  }, status);
}

function now() {
  return new Date().toISOString();
}

function id() {
  return crypto.randomUUID();
}

function clean(value, max = 5000) {
  if (value === undefined || value === null) return "";
  return String(value).trim().slice(0, max);
}

function numberOrNull(value) {
  if (value === undefined || value === null || value === "") {
    return null;
  }

  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function integerOrNull(value) {
  const n = numberOrNull(value);
  return n === null ? null : Math.floor(n);
}

function normalizePhotos(value) {
  let photos = value;

  if (typeof photos === "string") {
    try {
      photos = JSON.parse(photos);
    } catch {
      photos = photos
        .split(",")
        .map(x => x.trim())
        .filter(Boolean);
    }
  }

  if (!Array.isArray(photos)) {
    return [];
  }

  return photos
    .map(x => clean(x, 2000))
    .filter(Boolean)
    .slice(0, MAX_PHOTOS);
}

function normalizeFeatures(value) {
  let features = value;

  if (typeof features === "string") {
    try {
      features = JSON.parse(features);
    } catch {
      features = features
        .split(",")
        .map(x => x.trim())
        .filter(Boolean);
    }
  }

  if (!Array.isArray(features)) {
    return [];
  }

  return features
    .map(x => clean(x, 200))
    .filter(Boolean)
    .slice(0, 50);
}

async function parseBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

async function ensureDatabase(env) {
  if (!env.DB) {
    throw new Error("D1 database binding DB is missing.");
  }

  await env.DB.batch([
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        phone TEXT,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `),

    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL
      )
    `),

    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS listings (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        title TEXT NOT NULL,
        property_type TEXT NOT NULL,
        purpose TEXT NOT NULL,
        price REAL NOT NULL,
        location TEXT NOT NULL,
        bedrooms INTEGER,
        bathrooms INTEGER,
        area REAL,
        description TEXT,
        features TEXT,
        photos TEXT,
        agent_name TEXT,
        phone TEXT,
        email TEXT,
        owner_type TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        views INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `),

    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS inquiries (
        id TEXT PRIMARY KEY,
        listing_id TEXT NOT NULL,
        user_id TEXT,
        name TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        message TEXT,
        status TEXT NOT NULL DEFAULT 'new',
        created_at TEXT NOT NULL
      )
    `),

    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS favorites (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        listing_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(user_id, listing_id)
      )
    `)
  ]);

  return true;
}

async function hashPassword(password) {
  const encoder = new TextEncoder();

  const salt = crypto.getRandomValues(new Uint8Array(16));

  const baseKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    baseKey,
    256
  );

  return `${toBase64(salt)}:${toBase64(new Uint8Array(bits))}`;
}

async function verifyPassword(password, stored) {
  try {
    const [saltText, hashText] = stored.split(":");

    const salt = fromBase64(saltText);
    const expected = fromBase64(hashText);

    const encoder = new TextEncoder();

    const baseKey = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256"
      },
      baseKey,
      256
    );

    const actual = new Uint8Array(bits);

    if (actual.length !== expected.length) {
      return false;
    }

    let difference = 0;

    for (let i = 0; i < actual.length; i++) {
      difference |= actual[i] ^ expected[i];
    }

    return difference === 0;
  } catch {
    return false;
  }
}

function toBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function getBearerToken(request) {
  const header = request.headers.get("Authorization") || "";

  if (!header.toLowerCase().startsWith("bearer ")) {
    return null;
  }

  return header.slice(7).trim() || null;
}

async function getCurrentUser(request, env) {
  const token = getBearerToken(request);

  if (!token) {
    return null;
  }

  const session = await env.DB.prepare(`
    SELECT
      sessions.id,
      sessions.user_id,
      sessions.expires_at,
      users.name,
      users.email,
      users.phone,
      users.role
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.id = ?
      AND sessions.expires_at > ?
  `)
    .bind(token, now())
    .first();

  return session || null;
}

async function requireUser(request, env) {
  const user = await getCurrentUser(request, env);

  if (!user) {
    return {
      ok: false,
      response: error("Authentication required.", 401)
    };
  }

  return {
    ok: true,
    user
  };
}

function validateListing(data) {
  const required = [
    ["title", "Property title"],
    ["property_type", "Property type"],
    ["purpose", "Purpose"],
    ["location", "Location"]
  ];

  for (const [field, label] of required) {
    if (!clean(data[field])) {
      return `${label} is required.`;
    }
  }

  const price = numberOrNull(data.price);

  if (price === null || price < 0) {
    return "A valid property price is required.";
  }

  const purpose = clean(data.purpose).toLowerCase();

  if (!["sale", "rent", "shortlet", "lease"].includes(purpose)) {
    return "Invalid property purpose.";
  }

  const photos = normalizePhotos(data.photos);

  if (photos.length > MAX_PHOTOS) {
    return `A maximum of ${MAX_PHOTOS} photos is allowed.`;
  }

  return null;
}

function listingResponse(row) {
  if (!row) return null;

  return {
    id: row.id,
    title: row.title,
    property_type: row.property_type,
    purpose: row.purpose,
    price: row.price,
    location: row.location,
    bedrooms: row.bedrooms,
    bathrooms: row.bathrooms,
    area: row.area,
    description: row.description || "",
    features: normalizeFeatures(row.features),
    photos: normalizePhotos(row.photos),
    agent_name: row.agent_name || "",
    phone: row.phone || "",
    email: row.email || "",
    owner_type: row.owner_type || "",
    status: row.status,
    views: row.views || 0,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

async function registerUser(request, env) {
  const data = await parseBody(request);

  if (!data) {
    return error("Invalid JSON.");
  }

  const name = clean(data.name, 120);
  const email = clean(data.email, 200).toLowerCase();
  const phone = clean(data.phone, 50);
  const password = String(data.password || "");

  if (!name || !email || !password) {
    return error("Name, email and password are required.");
  }

  if (password.length < 8) {
    return error("Password must be at least 8 characters.");
  }

  const existing = await env.DB.prepare(
    "SELECT id FROM users WHERE email = ?"
  )
    .bind(email)
    .first();

  if (existing) {
    return error("An account with this email already exists.", 409);
  }

  const userId = id();
  const timestamp = now();
  const passwordHash = await hashPassword(password);

  await env.DB.prepare(`
    INSERT INTO users
    (id, name, email, phone, password_hash, role, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, 'user', ?, ?)
  `)
    .bind(
      userId,
      name,
      email,
      phone,
      passwordHash,
      timestamp,
      timestamp
    )
    .run();

  return json({
    success: true,
    message: "Account created successfully.",
    user: {
      id: userId,
      name,
      email,
      phone,
      role: "user"
    }
  }, 201);
}

async function loginUser(request, env) {
  const data = await parseBody(request);

  if (!data) {
    return error("Invalid JSON.");
  }

  const email = clean(data.email, 200).toLowerCase();
  const password = String(data.password || "");

  if (!email || !password) {
    return error("Email and password are required.");
  }

  const user = await env.DB.prepare(
    "SELECT * FROM users WHERE email = ?"
  )
    .bind(email)
    .first();

  if (!user) {
    return error("Invalid email or password.", 401);
  }

  const valid = await verifyPassword(password, user.password_hash);

  if (!valid) {
    return error("Invalid email or password.", 401);
  }

  const token = id();
  const timestamp = now();
  const expiry = new Date(
    Date.now() + SESSION_DAYS * 86400000
  ).toISOString();

  await env.DB.prepare(`
    INSERT INTO sessions
    (id, user_id, expires_at, created_at)
    VALUES (?, ?, ?, ?)
  `)
    .bind(token, user.id, expiry, timestamp)
    .run();

  return json({
    success: true,
    token,
    expires_at: expiry,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      role: user.role
    }
  });
}

async function logoutUser(request, env) {
  const token = getBearerToken(request);

  if (token) {
    await env.DB.prepare(
      "DELETE FROM sessions WHERE id = ?"
    )
      .bind(token)
      .run();
  }

  return json({
    success: true,
    message: "Logged out successfully."
  });
}

async function createListing(request, env) {
  const auth = await requireUser(request, env);

  if (!auth.ok) {
    return auth.response;
  }

  const data = await parseBody(request);

  if (!data) {
    return error("Invalid JSON.");
  }

  const validationError = validateListing(data);

  if (validationError) {
    return error(validationError);
  }

  const listingId = id();
  const timestamp = now();

  const photos = normalizePhotos(data.photos);
  const features = normalizeFeatures(data.features);

  await env.DB.prepare(`
    INSERT INTO listings (
      id,
      user_id,
      title,
      property_type,
      purpose,
      price,
      location,
      bedrooms,
      bathrooms,
      area,
      description,
      features,
      photos,
      agent_name,
      phone,
      email,
      owner_type,
      status,
      views,
      created_at,
      updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?)
  `)
    .bind(
      listingId,
      auth.user.user_id,
      clean(data.title, 200),
      clean(data.property_type, 100),
      clean(data.purpose, 50).toLowerCase(),
      numberOrNull(data.price),
      clean(data.location, 300),
      integerOrNull(data.bedrooms),
      integerOrNull(data.bathrooms),
      numberOrNull(data.area),
      clean(data.description, 10000),
      JSON.stringify(features),
      JSON.stringify(photos),
      clean(data.agent_name, 150),
      clean(data.phone, 50),
      clean(data.email, 200),
      clean(data.owner_type, 80),
      timestamp,
      timestamp
    )
    .run();

  return json({
    success: true,
    message: "Property submitted successfully and is awaiting approval.",
    listing: {
      id: listingId,
      status: "pending"
    }
  }, 201);
}

async function getListings(request, env) {
  const url = new URL(request.url);

  const purpose = clean(url.searchParams.get("purpose"), 50);
  const propertyType = clean(
    url.searchParams.get("property_type"),
    100
  );
  const location = clean(
    url.searchParams.get("location"),
    300
  );
  const minPrice = numberOrNull(
    url.searchParams.get("min_price")
  );
  const maxPrice = numberOrNull(
    url.searchParams.get("max_price")
  );
  const bedrooms = integerOrNull(
    url.searchParams.get("bedrooms")
  );
  const bathrooms = integerOrNull(
    url.searchParams.get("bathrooms")
  );

  const limit = Math.min(
    Math.max(
      integerOrNull(url.searchParams.get("limit")) || 20,
      1
    ),
    100
  );

  const offset = Math.max(
    integerOrNull(url.searchParams.get("offset")) || 0,
    0
  );

  const conditions = ["status = 'approved'"];
  const bindings = [];

  if (purpose) {
    conditions.push("purpose = ?");
    bindings.push(purpose.toLowerCase());
  }

  if (propertyType) {
    conditions.push("LOWER(property_type) LIKE ?");
    bindings.push(`%${propertyType.toLowerCase()}%`);
  }

  if (location) {
    conditions.push("LOWER(location) LIKE ?");
    bindings.push(`%${location.toLowerCase()}%`);
  }

  if (minPrice !== null) {
    conditions.push("price >= ?");
    bindings.push(minPrice);
  }

  if (maxPrice !== null) {
    conditions.push("price <= ?");
    bindings.push(maxPrice);
  }

  if (bedrooms !== null) {
    conditions.push("bedrooms >= ?");
    bindings.push(bedrooms);
  }

  if (bathrooms !== null) {
    conditions.push("bathrooms >= ?");
    bindings.push(bathrooms);
  }

  const where = conditions.join(" AND ");

  const countQuery = `
    SELECT COUNT(*) AS total
    FROM listings
    WHERE ${where}
  `;

  const listQuery = `
    SELECT *
    FROM listings
    WHERE ${where}
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `;

  const countResult = await env.DB.prepare(countQuery)
    .bind(...bindings)
    .first();

  const rows = await env.DB.prepare(listQuery)
    .bind(...bindings, limit, offset)
    .all();

  return json({
    success: true,
    total: countResult?.total || 0,
    limit,
    offset,
    listings: (rows.results || []).map(listingResponse)
  });
}

async function getListing(request, env, listingId) {
  const row = await env.DB.prepare(`
    SELECT *
    FROM listings
    WHERE id = ?
  `)
    .bind(listingId)
    .first();

  if (!row) {
    return error("Property not found.", 404);
  }

  await env.DB.prepare(`
    UPDATE listings
    SET views = views + 1
    WHERE id = ?
  `)
    .bind(listingId)
    .run();

  row.views = (row.views || 0) + 1;

  return json({
    success: true,
    listing: listingResponse(row)
  });
}

async function updateListing(request, env, listingId) {
  const auth = await requireUser(request, env);

  if (!auth.ok) {
    return auth.response;
  }

  const existing = await env.DB.prepare(`
    SELECT *
    FROM listings
    WHERE id = ?
  `)
    .bind(listingId)
    .first();

  if (!existing) {
    return error("Property not found.", 404);
  }

  const isOwner = existing.user_id === auth.user.user_id;
  const isAdmin = auth.user.role === "admin";

  if (!isOwner && !isAdmin) {
    return error("You are not allowed to update this listing.", 403);
  }

  const data = await parseBody(request);

  if (!data) {
    return error("Invalid JSON.");
  }

  const merged = {
    title: data.title ?? existing.title,
    property_type:
      data.property_type ?? existing.property_type,
    purpose:
      data.purpose ?? existing.purpose,
    price:
      data.price ?? existing.price,
    location:
      data.location ?? existing.location,
    photos:
      data.photos ?? existing.photos,
    description:
      data.description ?? existing.description
  };

  const validationError = validateListing(merged);

  if (validationError) {
    return error(validationError);
  }

  const updated = now();

  await env.DB.prepare(`
    UPDATE listings
    SET
      title = ?,
      property_type = ?,
      purpose = ?,
      price = ?,
      location = ?,
      bedrooms = ?,
      bathrooms = ?,
      area = ?,
      description = ?,
      features = ?,
      photos = ?,
      agent_name = ?,
      phone = ?,
      email = ?,
      owner_type = ?,
      updated_at = ?
    WHERE id = ?
  `)
    .bind(
      clean(data.title ?? existing.title, 200),
      clean(
        data.property_type ?? existing.property_type,
        100
      ),
      clean(
        data.purpose ?? existing.purpose,
        50
      ).toLowerCase(),
      numberOrNull(data.price ?? existing.price),
      clean(
        data.location ?? existing.location,
        300
      ),
      integerOrNull(
        data.bedrooms ?? existing.bedrooms
      ),
      integerOrNull(
        data.bathrooms ?? existing.bathrooms
      ),
      numberOrNull(
        data.area ?? existing.area
      ),
      clean(
        data.description ?? existing.description,
        10000
      ),
      JSON.stringify(
        normalizeFeatures(
          data.features ?? existing.features
        )
      ),
      JSON.stringify(
        normalizePhotos(
          data.photos ?? existing.photos
        )
      ),
      clean(
        data.agent_name ?? existing.agent_name,
        150
      ),
      clean(
        data.phone ?? existing.phone,
        50
      ),
      clean(
        data.email ?? existing.email,
        200
      ),
      clean(
        data.owner_type ?? existing.owner_type,
        80
      ),
      updated,
      listingId
    )
    .run();

  return json({
    success: true,
    message: "Property updated successfully."
  });
}

async function deleteListing(request, env, listingId) {
  const auth = await requireUser(request, env);

  if (!auth.ok) {
    return auth.response;
  }

  const existing = await env.DB.prepare(`
    SELECT *
    FROM listings
    WHERE id = ?
  `)
    .bind(listingId)
    .first();

  if (!existing) {
    return error("Property not found.", 404);
  }

  const isOwner = existing.user_id === auth.user.user_id;
  const isAdmin = auth.user.role === "admin";

  if (!isOwner && !isAdmin) {
    return error("You are not allowed to delete this listing.", 403);
  }

  await env.DB.prepare(
    "DELETE FROM listings WHERE id = ?"
  )
    .bind(listingId)
    .run();

  return json({
    success: true,
    message: "Property deleted successfully."
  });
}

async function createInquiry(request, env, listingId) {
  const listing = await env.DB.prepare(`
    SELECT id, title
    FROM listings
    WHERE id = ?
  `)
    .bind(listingId)
    .first();

  if (!listing) {
    return error("Property not found.", 404);
  }

  const data = await parseBody(request);

  if (!data) {
    return error("Invalid JSON.");
  }

  const name = clean(data.name, 150);
  const email = clean(data.email, 200);
  const phone = clean(data.phone, 50);
  const message = clean(data.message, 5000);

  if (!name) {
    return error("Name is required.");
  }

  const authUser = await getCurrentUser(request, env);

  const inquiryId = id();

  await env.DB.prepare(`
    INSERT INTO inquiries
    (id, listing_id, user_id, name, email, phone, message, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'new', ?)
  `)
    .bind(
      inquiryId,
      listingId,
      authUser?.user_id || null,
      name,
      email,
      phone,
      message,
      now()
    )
    .run();

  return json({
    success: true,
    message: "Your property enquiry has been received.",
    inquiry_id: inquiryId,
    property: listing.title
  }, 201);
}

async function addFavorite(request, env, listingId) {
  const auth = await requireUser(request, env);

  if (!auth.ok) {
    return auth.response;
  }

  const listing = await env.DB.prepare(
    "SELECT id FROM listings WHERE id = ?"
  )
    .bind(listingId)
    .first();

  if (!listing) {
    return error("Property not found.", 404);
  }

  await env.DB.prepare(`
    INSERT OR IGNORE INTO favorites
    (id, user_id, listing_id, created_at)
    VALUES (?, ?, ?, ?)
  `)
    .bind(
      id(),
      auth.user.user_id,
      listingId,
      now()
    )
    .run();

  return json({
    success: true,
    message: "Property saved."
  });
}

async function removeFavorite(request, env, listingId) {
  const auth = await requireUser(request, env);

  if (!auth.ok) {
    return auth.response;
  }

  await env.DB.prepare(`
    DELETE FROM favorites
    WHERE user_id = ?
      AND listing_id = ?
  `)
    .bind(auth.user.user_id, listingId)
    .run();

  return json({
    success: true,
    message: "Property removed from saved properties."
  });
}

async function getFavorites(request, env) {
  const auth = await requireUser(request, env);

  if (!auth.ok) {
    return auth.response;
  }

  const rows = await env.DB.prepare(`
    SELECT listings.*
    FROM favorites
    JOIN listings
      ON listings.id = favorites.listing_id
    WHERE favorites.user_id = ?
    ORDER BY favorites.created_at DESC
  `)
    .bind(auth.user.user_id)
    .all();

  return json({
    success: true,
    listings: (rows.results || []).map(listingResponse)
  });
}

async function adminRequired(request, env) {
  const configuredKey = env.ADMIN_KEY;

  if (!configuredKey) {
    return error(
      "Admin access is not configured. Add ADMIN_KEY in Worker secrets.",
      503
    );
  }

  const suppliedKey =
    request.headers.get("X-Admin-Key") || "";

  if (
    !suppliedKey ||
    suppliedKey !== configuredKey
  ) {
    return error("Invalid admin key.", 403);
  }

  return null;
}

async function adminListings(request, env) {
  const denied = await adminRequired(request, env);

  if (denied) {
    return denied;
  }

  const url = new URL(request.url);

  const status =
    clean(url.searchParams.get("status"), 50);

  let query = `
    SELECT *
    FROM listings
  `;

  const bindings = [];

  if (status) {
    query += " WHERE status = ?";
    bindings.push(status);
  }

  query += " ORDER BY created_at DESC LIMIT 200";

  const rows = await env.DB.prepare(query)
    .bind(...bindings)
    .all();

  return json({
    success: true,
    listings: (rows.results || []).map(listingResponse)
  });
}

async function adminSetListingStatus(
  request,
  env,
  listingId
) {
  const denied = await adminRequired(request, env);

  if (denied) {
    return denied;
  }

  const data = await parseBody(request);

  if (!data) {
    return error("Invalid JSON.");
  }

  const status = clean(data.status, 50);

  const allowed = [
    "pending",
    "approved",
    "rejected",
    "sold",
    "rented",
    "archived"
  ];

  if (!allowed.includes(status)) {
    return error("Invalid listing status.");
  }

  const result = await env.DB.prepare(`
    UPDATE listings
    SET status = ?, updated_at = ?
    WHERE id = ?
  `)
    .bind(status, now(), listingId)
    .run();

  if (!result.success) {
    return error("Unable to update listing.", 500);
  }

  return json({
    success: true,
    message: `Listing status changed to ${status}.`
  });
}

async function adminInquiries(request, env) {
  const denied = await adminRequired(request, env);

  if (denied) {
    return denied;
  }

  const rows = await env.DB.prepare(`
    SELECT
      inquiries.*,
      listings.title AS property_title
    FROM inquiries
    LEFT JOIN listings
      ON listings.id = inquiries.listing_id
    ORDER BY inquiries.created_at DESC
    LIMIT 500
  `).all();

  return json({
    success: true,
    inquiries: rows.results || []
  });
}

async function adminUsers(request, env) {
  const denied = await adminRequired(request, env);

  if (denied) {
    return denied;
  }

  const rows = await env.DB.prepare(`
    SELECT
      id,
      name,
      email,
      phone,
      role,
      created_at,
      updated_at
    FROM users
    ORDER BY created_at DESC
    LIMIT 500
  `).all();

  return json({
    success: true,
    users: rows.results || []
  });
}

async function adminStats(request, env) {
  const denied = await adminRequired(request, env);

  if (denied) {
    return denied;
  }

  const result = await env.DB.batch([
    env.DB.prepare(
      "SELECT COUNT(*) AS total FROM listings"
    ),
    env.DB.prepare(
      "SELECT COUNT(*) AS approved FROM listings WHERE status = 'approved'"
    ),
    env.DB.prepare(
      "SELECT COUNT(*) AS pending FROM listings WHERE status = 'pending'"
    ),
    env.DB.prepare(
      "SELECT COUNT(*) AS users FROM users"
    ),
    env.DB.prepare(
      "SELECT COUNT(*) AS inquiries FROM inquiries"
    ),
    env.DB.prepare(
      "SELECT COALESCE(SUM(views), 0) AS views FROM listings"
    )
  ]);

  return json({
    success: true,
    stats: {
      listings: result[0]?.results?.[0]?.total || 0,
      approved: result[1]?.results?.[0]?.approved || 0,
      pending: result[2]?.results?.[0]?.pending || 0,
      users: result[3]?.results?.[0]?.users || 0,
      inquiries: result[4]?.results?.[0]?.inquiries || 0,
      views: result[5]?.results?.[0]?.views || 0
    }
  });
}

async function health(env) {
  let database = false;

  try {
    await env.DB.prepare(
      "SELECT 1 AS ok"
    ).first();

    database = true;
  } catch {
    database = false;
  }

  return json({
    success: true,
    service: "Property Marketplace API",
    status: database ? "healthy" : "database_error",
    database,
    timestamp: now()
  });
}

async function status(env) {
  let database = false;

  try {
    await env.DB.prepare(
      "SELECT 1 AS ok"
    ).first();

    database = true;
  } catch {
    database = false;
  }

  return json({
    success: true,
    api: "property-marketplace-api",
    database,
    max_photos: MAX_PHOTOS,
    session_days: SESSION_DAYS,
    timestamp: now()
  });
}

async function route(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method.toUpperCase();

  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: CORS_HEADERS
    });
  }

  try {
    await ensureDatabase(env);

    if (
      path === "/" ||
      path === "/api" ||
      path === "/api/"
    ) {
      return json({
        success: true,
        name: "Property Marketplace API",
        version: "1.0.0",
        status: "online"
      });
    }

    if (path === "/api/health") {
      return await health(env);
    }

    if (path === "/api/status") {
      return await status(env);
    }

    if (
      path === "/api/auth/register" &&
      method === "POST"
    ) {
      return await registerUser(request, env);
    }

    if (
      path === "/api/auth/login" &&
      method === "POST"
    ) {
      return await loginUser(request, env);
    }

    if (
      path === "/api/auth/logout" &&
      method === "POST"
    ) {
      return await logoutUser(request, env);
    }

    if (
      path === "/api/auth/me" &&
      method === "GET"
    ) {
      const user = await getCurrentUser(request, env);

      return json({
        success: true,
        authenticated: !!user,
        user: user
          ? {
              id: user.user_id,
              name: user.name,
              email: user.email,
              phone: user.phone,
              role: user.role
            }
          : null
      });
    }

    if (
      path === "/api/listings" &&
      method === "GET"
    ) {
      return await getListings(request, env);
    }

    if (
      path === "/api/listings" &&
      method === "POST"
    ) {
      return await createListing(request, env);
    }

    const listingMatch = path.match(
      /^\/api\/listings\/([^/]+)$/
    );

    if (listingMatch) {
      const listingId = listingMatch[1];

      if (method === "GET") {
        return await getListing(
          request,
          env,
          listingId
        );
      }

      if (
        method === "PUT" ||
        method === "PATCH"
      ) {
        return await updateListing(
          request,
          env,
          listingId
        );
      }

      if (method === "DELETE") {
        return await deleteListing(
          request,
          env,
          listingId
        );
      }
    }

    const inquiryMatch = path.match(
      /^\/api\/listings\/([^/]+)\/inquiries$/
    );

    if (
      inquiryMatch &&
      method === "POST"
    ) {
      return await createInquiry(
        request,
        env,
        inquiryMatch[1]
      );
    }

    const favoriteMatch = path.match(
      /^\/api\/listings\/([^/]+)\/favorite$/
    );

    if (favoriteMatch) {
      const listingId = favoriteMatch[1];

      if (method === "POST") {
        return await addFavorite(
          request,
          env,
          listingId
        );
      }

      if (method === "DELETE") {
        return await removeFavorite(
          request,
          env,
          listingId
        );
      }
    }

    if (
      path === "/api/favorites" &&
      method === "GET"
    ) {
      return await getFavorites(request, env);
    }

    if (
      path === "/api/admin/listings" &&
      method === "GET"
    ) {
      return await adminListings(request, env);
    }

    const adminStatusMatch = path.match(
      /^\/api\/admin\/listings\/([^/]+)\/status$/
    );

    if (
      adminStatusMatch &&
      method === "PATCH"
    ) {
      return await adminSetListingStatus(
        request,
        env,
        adminStatusMatch[1]
      );
    }

    if (
      path === "/api/admin/inquiries" &&
      method === "GET"
    ) {
      return await adminInquiries(request, env);
    }

    if (
      path === "/api/admin/users" &&
      method === "GET"
    ) {
      return await adminUsers(request, env);
    }

    if (
      path === "/api/admin/stats" &&
      method === "GET"
    ) {
      return await adminStats(request, env);
    }

    return error("API endpoint not found.", 404);

  } catch (err) {
    console.error(err);

    return error(
      "Internal server error.",
      500,
      {
        detail:
          err?.message ||
          "Unknown server error."
      }
    );
  }
}

export default {
  async fetch(request, env) {
    return route(request, env);
  }
};
