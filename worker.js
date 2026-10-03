const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Key"
};

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...CORS
    }
  });

const text = (body, status = 200, headers = {}) =>
  new Response(body, {
    status,
    headers: {
      ...CORS,
      ...headers
    }
  });

const now = () => new Date().toISOString();
const id = () => crypto.randomUUID();

async function ensureDatabase(env) {
  await env.DB.batch([
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      phone TEXT,
      role TEXT DEFAULT 'user',
      created_at TEXT NOT NULL
    )`),

    env.DB.prepare(`CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    )`),

    env.DB.prepare(`CREATE TABLE IF NOT EXISTS listings (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      title TEXT NOT NULL,
      property_type TEXT NOT NULL,
      purpose TEXT NOT NULL,
      price REAL NOT NULL,
      location TEXT NOT NULL,
      bedrooms INTEGER DEFAULT 0,
      bathrooms INTEGER DEFAULT 0,
      area REAL DEFAULT 0,
      description TEXT,
      features TEXT,
      photos TEXT,
      agent_name TEXT,
      phone TEXT,
      email TEXT,
      owner_type TEXT,
      status TEXT DEFAULT 'pending',
      views INTEGER DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )`),

    env.DB.prepare(`CREATE TABLE IF NOT EXISTS inquiries (
      id TEXT PRIMARY KEY,
      listing_id TEXT NOT NULL,
      name TEXT NOT NULL,
      email TEXT,
      phone TEXT,
      message TEXT,
      created_at TEXT NOT NULL
    )`),

    env.DB.prepare(`CREATE TABLE IF NOT EXISTS favorites (
      user_id TEXT NOT NULL,
      listing_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY(user_id, listing_id)
    )`)
  ]);
}

function normalizeListing(row) {
  if (!row) return null;

  return {
    ...row,
    price: Number(row.price || 0),
    bedrooms: Number(row.bedrooms || 0),
    bathrooms: Number(row.bathrooms || 0),
    area: Number(row.area || 0),
    views: Number(row.views || 0),
    features: safeJson(row.features, []),
    photos: safeJson(row.photos, [])
  };
}

function safeJson(value, fallback) {
  try {
    return value ? JSON.parse(value) : fallback;
  } catch {
    return fallback;
  }
}

function cleanFeatures(value) {
  if (Array.isArray(value)) {
    return value
      .map(String)
      .map(x => x.trim())
      .filter(Boolean)
      .slice(0, 30);
  }

  return String(value || "")
    .split(",")
    .map(x => x.trim())
    .filter(Boolean)
    .slice(0, 30);
}

function validListing(data) {
  return (
    data &&
    data.title &&
    data.property_type &&
    data.purpose &&
    data.location &&
    Number(data.price) > 0
  );
}

function getToken(request) {
  return (request.headers.get("Authorization") || "")
    .replace(/^Bearer\s+/i, "")
    .trim();
}

async function currentUser(request, env) {
  const token = getToken(request);

  if (!token) return null;

  const row = await env.DB.prepare(
    `SELECT u.*
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.id = ?
     AND s.expires_at > ?`
  )
    .bind(token, now())
    .first();

  return row || null;
}

async function hashPassword(password) {
  const enc = new TextEncoder();

  const salt = crypto.getRandomValues(
    new Uint8Array(16)
  );

  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
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
    key,
    256
  );

  const b64 = value =>
    btoa(
      String.fromCharCode(
        ...new Uint8Array(value)
      )
    );

  return `${b64(salt)}.${b64(bits)}`;
}

async function verifyPassword(password, stored) {
  try {
    const [s, p] = stored.split(".");

    const salt = Uint8Array.from(
      atob(s),
      c => c.charCodeAt(0)
    );

    const expected = Uint8Array.from(
      atob(p),
      c => c.charCodeAt(0)
    );

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt,
          iterations: 100000,
          hash: "SHA-256"
        },
        key,
        256
      )
    );

    return (
      bits.length === expected.length &&
      bits.every((v, i) => v === expected[i])
    );
  } catch {
    return false;
  }
}

function publicUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    role: user.role
  };
}

async function register(request, env) {
  const data = await request.json();

  if (
    !data.name ||
    !data.email ||
    !data.password
  ) {
    return json(
      {
        success: false,
        error:
          "Name, email and password are required."
      },
      400
    );
  }

  const email = String(data.email)
    .trim()
    .toLowerCase();

  if (data.password.length < 6) {
    return json(
      {
        success: false,
        error:
          "Password must be at least 6 characters."
      },
      400
    );
  }

  const exists = await env.DB.prepare(
    "SELECT id FROM users WHERE email = ?"
  )
    .bind(email)
    .first();

  if (exists) {
    return json(
      {
        success: false,
        error:
          "An account with this email already exists."
      },
      409
    );
  }

  const userId = id();
  const created = now();
  const passwordHash =
    await hashPassword(data.password);

  await env.DB.prepare(
    `INSERT INTO users
     (id, name, email, password_hash, phone, role, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      userId,
      String(data.name).trim(),
      email,
      passwordHash,
      data.phone || null,
      "user",
      created
    )
    .run();

  return json(
    {
      success: true,
      user: {
        id: userId,
        name: String(data.name).trim(),
        email,
        phone: data.phone || null,
        role: "user"
      }
    },
    201
  );
}

async function login(request, env) {
  const data = await request.json();

  const email = String(
    data.email || ""
  )
    .trim()
    .toLowerCase();

  const user = await env.DB.prepare(
    "SELECT * FROM users WHERE email = ?"
  )
    .bind(email)
    .first();

  if (
    !user ||
    !(await verifyPassword(
      String(data.password || ""),
      user.password_hash
    ))
  ) {
    return json(
      {
        success: false,
        error:
          "Invalid email or password."
      },
      401
    );
  }

  const token = id();
  const created = now();

  const expires = new Date(
    Date.now() +
      1000 * 60 * 60 * 24 * 30
  ).toISOString();

  await env.DB.prepare(
    `INSERT INTO sessions
     (id, user_id, created_at, expires_at)
     VALUES (?, ?, ?, ?)`
  )
    .bind(
      token,
      user.id,
      created,
      expires
    )
    .run();

  return json({
    success: true,
    token,
    user: publicUser(user)
  });
}

async function createListing(request, env) {
  const contentType =
    request.headers.get("content-type") || "";

  let data = {};
  let files = [];

  if (
    contentType.includes(
      "multipart/form-data"
    )
  ) {
    const formData =
      await request.formData();

    for (
      const [key, value]
      of formData.entries()
    ) {
      if (value instanceof File) {
        if (
          key === "photos" &&
          value.size > 0
        ) {
          files.push(value);
        }
      } else {
        data[key] = value;
      }
    }
  } else {
    data = await request.json();
  }

  files = files.slice(0, 6);

  if (!validListing(data)) {
    return json(
      {
        success: false,
        error:
          "Please complete the required property details."
      },
      400
    );
  }

  if (
    files.some(
      file =>
        !file.type.startsWith("image/")
    )
  ) {
    return json(
      {
        success: false,
        error:
          "Only image files are allowed."
      },
      400
    );
  }

  if (
    files.some(
      file =>
        file.size >
        8 * 1024 * 1024
    )
  ) {
    return json(
      {
        success: false,
        error:
          "Each image must be 8MB or smaller."
      },
      400
    );
  }

  const listingId = id();
  const stamp = Date.now();
  const photos = [];

  for (
    let i = 0;
    i < files.length;
    i++
  ) {
    const file = files[i];

    const ext = (
      file.name.split(".").pop() ||
      "jpg"
    )
      .toLowerCase()
      .replace(
        /[^a-z0-9]/g,
        ""
      );

    const key =
      `listings/${listingId}/` +
      `${String(i + 1).padStart(2, "0")}-` +
      `${stamp}.${ext || "jpg"}`;

    await env.IMAGES.put(
      key,
      file.stream(),
      {
        httpMetadata: {
          contentType:
            file.type ||
            "image/jpeg",
          cacheControl:
            "public, max-age=31536000"
        }
      }
    );

    photos.push(
      `/api/images/${encodeURIComponent(
        key
      )}`
    );
  }

  const user =
    await currentUser(
      request,
      env
    );

  const timestamp = now();

  const features =
    cleanFeatures(
      data.features
    );

  await env.DB.prepare(`
    INSERT INTO listings
    (
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
    VALUES (
      ?,?,?,?,?,?,?,?,?,?,
      ?,?,?,?,?,?,?,?,?,?,?
    )
  `)
    .bind(
      listingId,
      user?.id || null,
      String(data.title).trim(),
      String(
        data.property_type
      ).trim(),
      String(
        data.purpose
      ).trim(),
      Number(data.price) || 0,
      String(
        data.location
      ).trim(),
      Number(data.bedrooms) || 0,
      Number(data.bathrooms) || 0,
      Number(data.area) || 0,
      String(
        data.description || ""
      ).trim(),
      JSON.stringify(features),
      JSON.stringify(photos),
      String(
        data.agent_name || ""
      ).trim(),
      String(
        data.phone || ""
      ).trim(),
      String(
        data.email || ""
      ).trim(),
      String(
        data.owner_type || ""
      ).trim(),
      "pending",
      0,
      timestamp,
      timestamp
    )
    .run();

  return json(
    {
      success: true,
      listing:
        normalizeListing({
          id: listingId,
          user_id:
            user?.id || null,
          title:
            String(
              data.title
            ).trim(),
          property_type:
            String(
              data.property_type
            ).trim(),
          purpose:
            String(
              data.purpose
            ).trim(),
          price:
            Number(
              data.price
            ) || 0,
          location:
            String(
              data.location
            ).trim(),
          bedrooms:
            Number(
              data.bedrooms
            ) || 0,
          bathrooms:
            Number(
              data.bathrooms
            ) || 0,
          area:
            Number(
              data.area
            ) || 0,
          description:
            String(
              data.description ||
              ""
            ).trim(),
          features:
            JSON.stringify(
              features
            ),
          photos:
            JSON.stringify(
              photos
            ),
          agent_name:
            String(
              data.agent_name ||
              ""
            ).trim(),
          phone:
            String(
              data.phone || ""
            ).trim(),
          email:
            String(
              data.email || ""
            ).trim(),
          owner_type:
            String(
              data.owner_type ||
              ""
            ).trim(),
          status: "pending",
          views: 0,
          created_at:
            timestamp,
          updated_at:
            timestamp
        })
    },
    201
  );
}

function imageKeyFromPath(path) {
  const raw =
    decodeURIComponent(
      path.replace(
        /^\/api\/images\//,
        ""
      )
    );

  if (
    !raw ||
    raw.includes("..") ||
    raw.startsWith("/")
  ) {
    return null;
  }

  return raw;
}

async function serveImage(
  request,
  env,
  pathname
) {
  const key =
    imageKeyFromPath(
      pathname
    );

  if (!key) {
    return text(
      "Not found",
      404
    );
  }

  const object =
    await env.IMAGES.get(
      key
    );

  if (!object) {
    return text(
      "Image not found",
      404
    );
  }

  const headers =
    new Headers(CORS);

  object.writeHttpMetadata(
    headers
  );

  headers.set(
    "etag",
    object.httpEtag
  );

  headers.set(
    "Cache-Control",
    "public, max-age=31536000, immutable"
  );

  return new Response(
    object.body,
    { headers }
  );
}

async function listListings(
  request,
  env,
  url
) {
  const where = [
    "status = 'approved'"
  ];

  const binds = [];

  const add = (
    sql,
    value
  ) => {
    where.push(sql);
    binds.push(value);
  };

  if (
    url.searchParams.get(
      "purpose"
    )
  ) {
    add(
      "purpose = ?",
      url.searchParams.get(
        "purpose"
      )
    );
  }

  if (
    url.searchParams.get(
      "property_type"
    )
  ) {
    add(
      "property_type = ?",
      url.searchParams.get(
        "property_type"
      )
    );
  }

  if (
    url.searchParams.get(
      "location"
    )
  ) {
    add(
      "location LIKE ?",
      `%${url.searchParams.get(
        "location"
      )}%`
    );
  }

  if (
    url.searchParams.get(
      "min_price"
    )
  ) {
    add(
      "price >= ?",
      Number(
        url.searchParams.get(
          "min_price"
        )
      )
    );
  }

  if (
    url.searchParams.get(
      "max_price"
    )
  ) {
    add(
      "price <= ?",
      Number(
        url.searchParams.get(
          "max_price"
        )
      )
    );
  }

  if (
    url.searchParams.get(
      "bedrooms"
    )
  ) {
    add(
      "bedrooms >= ?",
      Number(
        url.searchParams.get(
          "bedrooms"
        )
      )
    );
  }

  if (
    url.searchParams.get(
      "bathrooms"
    )
  ) {
    add(
      "bathrooms >= ?",
      Number(
        url.searchParams.get(
          "bathrooms"
        )
      )
    );
  }

  const limit =
    Math.min(
      Math.max(
        Number(
          url.searchParams.get(
            "limit"
          ) || 30
        ),
        1
      ),
      100
    );

  const page =
    Math.max(
      Number(
        url.searchParams.get(
          "page"
        ) || 1
      ),
      1
    );

  const offset =
    (page - 1) *
    limit;

  const sql = `
    SELECT *
    FROM listings
    WHERE ${where.join(
      " AND "
    )}
    ORDER BY created_at DESC
    LIMIT ?
    OFFSET ?
  `;

  const result =
    await env.DB
      .prepare(sql)
      .bind(
        ...binds,
        limit,
        offset
      )
      .all();

  return json({
    success: true,
    listings:
      (
        result.results ||
        []
      ).map(
        normalizeListing
      ),
    page,
    limit
  });
}

async function getListing(
  request,
  env,
  idValue
) {
  const row =
    await env.DB
      .prepare(
        "SELECT * FROM listings WHERE id = ?"
      )
      .bind(idValue)
      .first();

  if (!row) {
    return json(
      {
        success: false,
        error:
          "Property not found."
      },
      404
    );
  }

  await env.DB
    .prepare(
      "UPDATE listings SET views = views + 1 WHERE id = ?"
    )
    .bind(idValue)
    .run();

  row.views =
    (row.views || 0) + 1;

  return json({
    success: true,
    listing:
      normalizeListing(row)
  });
}

async function updateListing(
  request,
  env,
  idValue
) {
  const user =
    await currentUser(
      request,
      env
    );

  if (!user) {
    return json(
      {
        success: false,
        error:
          "Sign in required."
      },
      401
    );
  }

  const existing =
    await env.DB
      .prepare(
        "SELECT * FROM listings WHERE id = ?"
      )
      .bind(idValue)
      .first();

  if (!existing) {
    return json(
      {
        success: false,
        error:
          "Property not found."
      },
      404
    );
  }

  if (
    existing.user_id !==
      user.id &&
    user.role !== "admin"
  ) {
    return json(
      {
        success: false,
        error:
          "Not authorized."
      },
      403
    );
  }

  const data =
    await request.json();

  const fields = [
    "title",
    "property_type",
    "purpose",
    "price",
    "location",
    "bedrooms",
    "bathrooms",
    "area",
    "description",
    "agent_name",
    "phone",
    "email",
    "owner_type"
  ];

  const sets = [];
  const values = [];

  for (
    const field of fields
  ) {
    if (
      data[field] !==
      undefined
    ) {
      sets.push(
        `${field} = ?`
      );

      values.push(
        [
          "price",
          "bedrooms",
          "bathrooms",
          "area"
        ].includes(field)
          ? Number(
              data[field]
            ) || 0
          : String(
              data[field] || ""
            )
      );
    }
  }

  if (
    data.features !==
    undefined
  ) {
    sets.push(
      "features = ?"
    );

    values.push(
      JSON.stringify(
        cleanFeatures(
          data.features
        )
      )
    );
  }

  if (!sets.length) {
    return json(
      {
        success: false,
        error:
          "Nothing to update."
      },
      400
    );
  }

  sets.push(
    "updated_at = ?"
  );

  values.push(now());
  values.push(idValue);

  await env.DB
    .prepare(
      `UPDATE listings
       SET ${sets.join(
         ", "
       )}
       WHERE id = ?`
    )
    .bind(...values)
    .run();

  const row =
    await env.DB
      .prepare(
        "SELECT * FROM listings WHERE id = ?"
      )
      .bind(idValue)
      .first();

  return json({
    success: true,
    listing:
      normalizeListing(row)
  });
}

async function deleteListing(
  request,
  env,
  idValue
) {
  const user =
    await currentUser(
      request,
      env
    );

  if (!user) {
    return json(
      {
        success: false,
        error:
          "Sign in required."
      },
      401
    );
  }

  const existing =
    await env.DB
      .prepare(
        "SELECT * FROM listings WHERE id = ?"
      )
      .bind(idValue)
      .first();

  if (!existing) {
    return json(
      {
        success:
                    "Property not found."
      },
      404
    );
  }

  if (
    existing.user_id !==
      user.id &&
    user.role !== "admin"
  ) {
    return json(
      {
        success: false,
        error:
          "Not authorized."
      },
      403
    );
  }

  const photos =
    safeJson(
      existing.photos,
      []
    );

  for (
    const photoUrl of photos
  ) {
    const match =
      String(
        photoUrl
      ).match(
        /\/api\/images\/(.+)$/
      );

    if (match) {
      try {
        await env.IMAGES.delete(
          decodeURIComponent(
            match[1]
          )
        );
      } catch {}
    }
  }

  await env.DB
    .prepare(
      "DELETE FROM listings WHERE id = ?"
    )
    .bind(idValue)
    .run();

  return json({
    success: true
  });
}

async function inquiry(
  request,
  env
) {
  const data =
    await request.json();

  if (
    !data.listing_id ||
    !data.name ||
    !data.message
  ) {
    return json(
      {
        success: false,
        error:
          "Listing, name and message are required."
      },
      400
    );
  }

  const listing =
    await env.DB
      .prepare(
        "SELECT id FROM listings WHERE id = ?"
      )
      .bind(data.listing_id)
      .first();

  if (!listing) {
    return json(
      {
        success: false,
        error:
          "Property not found."
      },
      404
    );
  }

  const inquiryId =
    id();

  await env.DB
    .prepare(
      `INSERT INTO inquiries
       (id, listing_id, name, email, phone, message, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      inquiryId,
      data.listing_id,
      String(
        data.name
      ).trim(),
      String(
        data.email || ""
      ).trim(),
      String(
        data.phone || ""
      ).trim(),
      String(
        data.message
      ).trim(),
      now()
    )
    .run();

  return json(
    {
      success: true,
      id: inquiryId
    },
    201
  );
}

async function favorite(
  request,
  env,
  listingId,
  method
) {
  const user =
    await currentUser(
      request,
      env
    );

  if (!user) {
    return json(
      {
        success: false,
        error:
          "Sign in required."
      },
      401
    );
  }

  if (
    method ===
    "DELETE"
  ) {
    await env.DB
      .prepare(
        `DELETE FROM favorites
         WHERE user_id = ?
         AND listing_id = ?`
      )
      .bind(
        user.id,
        listingId
      )
      .run();

    return json({
      success: true,
      favorited: false
    });
  }

  await env.DB
    .prepare(
      `INSERT OR IGNORE INTO favorites
       (user_id, listing_id, created_at)
       VALUES (?, ?, ?)`
    )
    .bind(
      user.id,
      listingId,
      now()
    )
    .run();

  return json({
    success: true,
    favorited: true
  });
}

async function admin(
  request,
  env,
  url
) {
  const key =
    env.ADMIN_KEY;

  if (
    !key ||
    request.headers.get(
      "X-Admin-Key"
    ) !== key
  ) {
    return json(
      {
        success: false,
        error:
          "Unauthorized."
      },
      401
    );
  }

  const path =
    url.pathname;

  if (
    path ===
    "/api/admin/stats"
  ) {
    const [
      listings,
      users,
      inquiries
    ] =
      await Promise.all([
        env.DB
          .prepare(
            "SELECT COUNT(*) AS n FROM listings"
          )
          .first(),

        env.DB
          .prepare(
            "SELECT COUNT(*) AS n FROM users"
          )
          .first(),

        env.DB
          .prepare(
            "SELECT COUNT(*) AS n FROM inquiries"
          )
          .first()
      ]);

    return json({
      success: true,
      stats: {
        listings:
          listings.n,
        users:
          users.n,
        inquiries:
          inquiries.n
      }
    });
  }

  if (
    path ===
    "/api/admin/listings"
  ) {
    const result =
      await env.DB
        .prepare(
          "SELECT * FROM listings ORDER BY created_at DESC"
        )
        .all();

    return json({
      success: true,
      listings:
        (
          result.results ||
          []
        ).map(
          normalizeListing
        )
    });
  }

  const match =
    path.match(
      /^\/api\/admin\/listings\/([^/]+)\/status$/
    );

  if (
    match &&
    request.method ===
      "PATCH"
  ) {
    const data =
      await request.json();

    if (
      ![
        "pending",
        "approved",
        "rejected"
      ].includes(
        data.status
      )
    ) {
      return json(
        {
          success: false,
          error:
            "Invalid status."
        },
        400
      );
    }

    await env.DB
      .prepare(
        `UPDATE listings
         SET status = ?, updated_at = ?
         WHERE id = ?`
      )
      .bind(
        data.status,
        now(),
        match[1]
      )
      .run();

    return json({
      success: true
    });
  }

  return json(
    {
      success: false,
      error:
        "Admin route not found."
    },
    404
  );
}

export default {
  async fetch(
    request,
    env
  ) {
    if (
      request.method ===
      "OPTIONS"
    ) {
      return new Response(
        null,
        {
          status: 204,
          headers: CORS
        }
      );
    }

    const url =
      new URL(
        request.url
      );

    try {
      await ensureDatabase(
        env
      );

      if (
        url.pathname ===
        "/"
      ) {
        return json({
          success: true,
          name:
            "Property Marketplace API",
          version:
            "2.0.0",
          status:
            "online"
        });
      }

      if (
        url.pathname ===
        "/health"
      ) {
        return json({
          success: true,
          status:
            "healthy",
          database:
            !!env.DB,
          images:
            !!env.IMAGES
        });
      }

      if (
        url.pathname.startsWith(
          "/api/images/"
        )
      ) {
        return serveImage(
          request,
          env,
          url.pathname
        );
      }

      if (
        url.pathname ===
          "/api/auth/register" &&
        request.method ===
          "POST"
      ) {
        return register(
          request,
          env
        );
      }

      if (
        url.pathname ===
          "/api/auth/login" &&
        request.method ===
          "POST"
      ) {
        return login(
          request,
          env
        );
      }

      if (
        url.pathname ===
          "/api/auth/me" &&
        request.method ===
          "GET"
      ) {
        return json({
          success: true,
          user:
            publicUser(
              await currentUser(
                request,
                env
              )
            )
        });
      }

      if (
        url.pathname ===
          "/api/auth/logout" &&
        request.method ===
          "POST"
      ) {
        const token =
          getToken(
            request
          );

        if (token) {
          await env.DB
            .prepare(
              "DELETE FROM sessions WHERE id = ?"
            )
            .bind(token)
            .run();
        }

        return json({
          success: true
        });
      }

      if (
        url.pathname ===
          "/api/listings" &&
        request.method ===
          "GET"
      ) {
        return listListings(
          request,
          env,
          url
        );
      }

      if (
        url.pathname ===
          "/api/listings" &&
        request.method ===
          "POST"
      ) {
        return createListing(
          request,
          env
        );
      }

      const listingMatch =
        url.pathname.match(
          /^\/api\/listings\/([^/]+)$/
        );

      if (listingMatch) {
        if (
          request.method ===
          "GET"
        ) {
          return getListing(
            request,
            env,
            listingMatch[1]
          );
        }

        if (
          [
            "PUT",
            "PATCH"
          ].includes(
            request.method
          )
        ) {
          return updateListing(
            request,
            env,
            listingMatch[1]
          );
        }

        if (
          request.method ===
          "DELETE"
        ) {
          return deleteListing(
            request,
            env,
            listingMatch[1]
          );
        }
      }

      if (
        url.pathname ===
          "/api/inquiries" &&
        request.method ===
          "POST"
      ) {
        return inquiry(
          request,
          env
        );
      }

      const favoriteMatch =
        url.pathname.match(
          /^\/api\/favorites\/([^/]+)$/
        );

      if (
        favoriteMatch &&
        [
          "POST",
          "DELETE"
        ].includes(
          request.method
        )
      ) {
        return favorite(
          request,
          env,
          favoriteMatch[1],
          request.method
        );
      }

      if (
        url.pathname.startsWith(
          "/api/admin/"
        )
      ) {
        return admin(
          request,
          env,
          url
        );
      }

      return json(
        {
          success: false,
          error:
            "Route not found."
        },
        404
      );

    } catch (error) {
      console.error(error);

      return json(
        {
          success: false,
          error:
            error?.message ||
            "Server error."
        },
        500
      );
    }
  }
};
