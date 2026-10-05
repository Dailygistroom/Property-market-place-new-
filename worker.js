const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...CORS_HEADERS,
    },
  });
}

function text(data, status = 200, contentType = "text/plain") {
  return new Response(data, {
    status,
    headers: {
      "Content-Type": contentType,
      ...CORS_HEADERS,
    },
  });
}

function now() {
  return new Date().toISOString();
}

function randomToken(bytes = 32) {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);

  return [...array]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function getBearerToken(request) {
  const header = request.headers.get("Authorization") || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.slice(7).trim() || null;
}

async function hashPassword(password) {
  const encoder = new TextEncoder();

  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
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
      hash: "SHA-256",
    },
    key,
    256
  );

  return {
    salt: toBase64(salt),
    hash: toBase64(new Uint8Array(bits)),
  };
}

async function verifyPassword(password, stored) {
  try {
    const [saltBase64, hashBase64] = String(stored).split(":");

    if (!saltBase64 || !hashBase64) {
      return false;
    }

    const salt = fromBase64(saltBase64);
    const expected = fromBase64(hashBase64);

    const encoder = new TextEncoder();

    const key = await crypto.subtle.importKey(
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
        hash: "SHA-256",
      },
      key,
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

function publicUser(user) {
  return {
    id: user.id,
    full_name: user.full_name,
    email: user.email,
    phone: user.phone,
    role: user.role,
    profile_image: user.profile_image,
    company_name: user.company_name,
    created_at: user.created_at,
  };
}

async function requireUser(request, env) {
  const token = getBearerToken(request);

  if (!token) {
    return null;
  }

  const result = await env.DB.prepare(`
    SELECT
      u.id,
      u.full_name,
      u.email,
      u.phone,
      u.role,
      u.profile_image,
      u.company_name,
      u.created_at
    FROM auth_sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token = ?
      AND s.expires_at > ?
    LIMIT 1
  `)
    .bind(token, now())
    .first();

  return result || null;
}

async function requireUserResponse(request, env) {
  const user = await requireUser(request, env);

  if (!user) {
    return {
      error: json(
        {
          success: false,
          message: "Authentication required.",
        },
        401
      ),
    };
  }

  return { user };
}

async function createSession(env, userId) {
  const token = randomToken(32);

  const expires = new Date(
    Date.now() + 30 * 24 * 60 * 60 * 1000
  ).toISOString();

  await env.DB.prepare(`
    INSERT INTO auth_sessions (
      user_id,
      token,
      expires_at
    )
    VALUES (?, ?, ?)
  `)
    .bind(userId, token, expires)
    .run();

  return token;
}

async function handleRegister(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        success: false,
        message: "Invalid JSON request.",
      },
      400
    );
  }

  const fullName = String(body.full_name || body.name || "").trim();
  const email = normalizeEmail(body.email);
  const phone = String(body.phone || "").trim();
  const role = String(body.role || "").trim().toLowerCase();
  const password = String(body.password || "");

  const allowedRoles = ["agent", "landlord", "developer"];

  if (!fullName || !email || !phone || !role || !password) {
    return json(
      {
        success: false,
        message: "Please complete all required fields.",
      },
      400
    );
  }

  if (!allowedRoles.includes(role)) {
    return json(
      {
        success: false,
        message: "Invalid account type.",
      },
      400
    );
  }

  if (password.length < 8) {
    return json(
      {
        success: false,
        message: "Password must be at least 8 characters.",
      },
      400
    );
  }

  const existing = await env.DB.prepare(`
    SELECT id
    FROM users
    WHERE email = ?
    LIMIT 1
  `)
    .bind(email)
    .first();

  if (existing) {
    return json(
      {
        success: false,
        message: "An account with this email already exists.",
      },
      409
    );
  }

  const { salt, hash } = await hashPassword(password);

  const passwordHash = `${salt}:${hash}`;

  const result = await env.DB.prepare(`
    INSERT INTO users (
      full_name,
      email,
      phone,
      password_hash,
      role
    )
    VALUES (?, ?, ?, ?, ?)
  `)
    .bind(
      fullName,
      email,
      phone,
      passwordHash,
      role
    )
    .run();

  const userId = result.meta.last_row_id;

  const user = await env.DB.prepare(`
    SELECT
      id,
      full_name,
      email,
      phone,
      role,
      profile_image,
      company_name,
      created_at
    FROM users
    WHERE id = ?
  `)
    .bind(userId)
    .first();

  return json(
    {
      success: true,
      message: "Account created successfully.",
      user: publicUser(user),
    },
    201
  );
}

async function handleLogin(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        success: false,
        message: "Invalid JSON request.",
      },
      400
    );
  }

  const email = normalizeEmail(body.email);
  const password = String(body.password || "");

  if (!email || !password) {
    return json(
      {
        success: false,
        message: "Email and password are required.",
      },
      400
    );
  }

  const user = await env.DB.prepare(`
    SELECT
      id,
      full_name,
      email,
      phone,
      password_hash,
      role,
      profile_image,
      company_name,
      created_at
    FROM users
    WHERE email = ?
    LIMIT 1
  `)
    .bind(email)
    .first();

  if (!user) {
    return json(
      {
        success: false,
        message: "Invalid email or password.",
      },
      401
    );
  }

  const valid = await verifyPassword(
    password,
    user.password_hash
  );

  if (!valid) {
    return json(
      {
        success: false,
        message: "Invalid email or password.",
      },
      401
    );
  }

  const token = await createSession(env, user.id);

  return json({
    success: true,
    token,
    user: publicUser(user),
  });
}

async function handleLogout(request, env) {
  const token = getBearerToken(request);

  if (token) {
    await env.DB.prepare(`
      DELETE FROM auth_sessions
      WHERE token = ?
    `)
      .bind(token)
      .run();
  }

  return json({
    success: true,
    message: "Logged out successfully.",
  });
}

async function handleMe(request, env) {
  const result = await requireUserResponse(request, env);

  if (result.error) {
    return result.error;
  }

  return json({
    success: true,
    user: publicUser(result.user),
  });
}

async function handlePlans(env) {
  const result = await env.DB.prepare(`
    SELECT
      id,
      name,
      description,
      price,
      duration_days,
      max_active_listings,
      is_active
    FROM listing_plans
    WHERE is_active = 1
    ORDER BY price ASC, id ASC
  `).all();

  return json({
    success: true,
    plans: result.results || [],
  });
}

function buildPropertyFilters(url) {
  const conditions = [
    `p.status = 'active'`,
  ];

  const params = [];

  const listingType = url.searchParams.get("listing_type");
  const propertyType = url.searchParams.get("property_type");
  const city = url.searchParams.get("city");
  const state = url.searchParams.get("state");
  const minPrice = url.searchParams.get("min_price");
  const maxPrice = url.searchParams.get("max_price");
  const bedrooms = url.searchParams.get("bedrooms");

  if (listingType) {
    conditions.push(`p.listing_type = ?`);
    params.push(listingType);
  }

  if (propertyType) {
    conditions.push(`p.property_type = ?`);
    params.push(propertyType);
  }

  if (city) {
    conditions.push(`LOWER(p.city) = LOWER(?)`);
    params.push(city);
  }

  if (state) {
    conditions.push(`LOWER(p.state) = LOWER(?)`);
    params.push(state);
  }

  if (minPrice !== null && minPrice !== "") {
    conditions.push(`p.price >= ?`);
    params.push(Number(minPrice));
  }

  if (maxPrice !== null && maxPrice !== "") {
    conditions.push(`p.price <= ?`);
    params.push(Number(maxPrice));
  }

  if (bedrooms !== null && bedrooms !== "") {
    conditions.push(`p.bedrooms >= ?`);
    params.push(Number(bedrooms));
  }

  return {
    where: conditions.join(" AND "),
    params,
  };
}

async function handleGetProperties(request, env) {
  const url = new URL(request.url);

  const limit = Math.min(
    Math.max(Number(url.searchParams.get("limit") || 20), 1),
    50
  );

  const page = Math.max(
    Number(url.searchParams.get("page") || 1),
    1
  );

  const offset = (page - 1) * limit;

  const filters = buildPropertyFilters(url);

  const query = `
    SELECT
      p.id,
      p.user_id,
      p.title,
      p.description,
      p.listing_type,
      p.property_type,
      p.price,
      p.currency,
      p.address,
      p.city,
      p.state,
      p.country,
      p.latitude,
      p.longitude,
      p.bedrooms,
      p.bathrooms,
      p.toilets,
      p.parking_spaces,
      p.size_value,
      p.size_unit,
      p.furnished,
      p.serviced,
      p.status,
      p.plan_type,
      p.listing_expires_at,
      p.is_featured,
      p.views,
      p.created_at,
      p.updated_at,
      u.full_name AS advertiser_name,
      u.phone AS advertiser_phone,
      u.email AS advertiser_email,
      u.company_name AS advertiser_company
    FROM properties p
    JOIN users u ON u.id = p.user_id
    WHERE ${filters.where}
    ORDER BY
      p.is_featured DESC,
      p.created_at DESC
    LIMIT ? OFFSET ?
  `;

  const result = await env.DB.prepare(query)
    .bind(...filters.params, limit, offset)
    .all();

  const properties = result.results || [];

  for (const property of properties) {
    const images = await env.DB.prepare(`
      SELECT
        id,
        image_key,
        image_url,
        sort_order
      FROM property_images
      WHERE property_id = ?
      ORDER BY sort_order ASC, id ASC
    `)
      .bind(property.id)
      .all();

    property.images = images.results || [];
  }

  return json({
    success: true,
    page,
    limit,
    properties,
  });
}

async function handleGetProperty(request, env, propertyId) {
  const property = await env.DB.prepare(`
    SELECT
      p.*,
      u.full_name AS advertiser_name,
      u.phone AS advertiser_phone,
      u.email AS advertiser_email,
      u.company_name AS advertiser_company,
      u.profile_image AS advertiser_image
    FROM properties p
    JOIN users u ON u.id = p.user_id
    WHERE p.id = ?
    LIMIT 1
  `)
    .bind(propertyId)
    .first();

  if (!property) {
    return json(
      {
        success: false,
        message: "Property not found.",
      },
      404
    );
  }

  await env.DB.prepare(`
    UPDATE properties
    SET views = views + 1,
        updated_at = ?
    WHERE id = ?
  `)
    .bind(now(), propertyId)
    .run();

  const images = await env.DB.prepare(`
    SELECT
      id,
      image_key,
      image_url,
      sort_order
    FROM property_images
    WHERE property_id = ?
    ORDER BY sort_order ASC, id ASC
  `)
    .bind(propertyId)
    .all();

  property.images = images.results || [];

  return json({
    success: true,
    property,
  });
}

async function handleCreateProperty(request, env) {
  const auth = await requireUserResponse(request, env);

  if (auth.error) {
    return auth.error;
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        success: false,
        message: "Invalid JSON request.",
      },
      400
    );
  }

  const user = auth.user;

  const title = String(body.title || "").trim();
  const description = String(body.description || "").trim();

  const listingType = String(
    body.listing_type ||
    body.category ||
    body.purpose ||
    ""
  ).trim().toLowerCase();

  const propertyType = String(
    body.property_type ||
    ""
  ).trim();

  const price = Number(body.price);

  const address = String(
    body.address ||
    body.location ||
    ""
  ).trim();

  const city = String(
    body.city ||
    body.location ||
    ""
  ).trim();

  const state = body.state
    ? String(body.state).trim()
    : null;

  const country = String(
    body.country || "Nigeria"
  ).trim();

  const bedrooms = Number(body.bedrooms || 0);
  const bathrooms = Number(body.bathrooms || 0);
  const toilets = Number(body.toilets || 0);
  const parkingSpaces = Number(body.parking_spaces || 0);

  const sizeValue =
    body.size_value === undefined ||
    body.size_value === ""
      ? null
      : Number(body.size_value);

  const sizeUnit = String(
    body.size_unit || "sqm"
  ).trim();

  const furnished = body.furnished ? 1 : 0;
  const serviced = body.serviced ? 1 : 0;

  const allowedListingTypes = [
    "sale",
    "rent",
    "land",
    "shortlet",
  ];

  if (!title || !description || !propertyType || !address || !city) {
    return json(
      {
        success: false,
        message: "Please complete all required property fields.",
      },
      400
    );
  }

  if (!allowedListingTypes.includes(listingType)) {
    return json(
      {
        success: false,
        message: "Invalid listing type.",
      },
      400
    );
  }

  if (!Number.isFinite(price) || price <= 0) {
    return json(
      {
        success: false,
        message: "Enter a valid property price.",
      },
      400
    );
  }

  const activeCount = await env.DB.prepare(`
    SELECT COUNT(*) AS count
    FROM properties
    WHERE user_id = ?
      AND status = 'active'
  `)
    .bind(user.id)
    .first();

  const count = Number(activeCount?.count || 0);

  /*
    The free plan allows the first three active listings.
    Paid listing plans can be introduced through the payment
    flow later.
  */

  if (count >= 3) {
    return json(
      {
        success: false,
        message:
          "You have reached the free listing limit. Please choose a paid listing plan.",
        code: "LISTING_LIMIT_REACHED",
      },
      403
    );
  }

  const result = await env.DB.prepare(`
    INSERT INTO properties (
      user_id,
      title,
      description,
      listing_type,
      property_type,
      price,
      currency,
      address,
      city,
      state,
      country,
      latitude,
      longitude,
      bedrooms,
      bathrooms,
      toilets,
      parking_spaces,
      size_value,
      size_unit,
      furnished,
      serviced,
      status,
      plan_type
    )
    VALUES (
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 'free'
    )
  `)
    .bind(
      user.id,
      title,
      description,
      listingType,
      propertyType,
      price,
      "NGN",
      address,
      city,
      state,
      country,
      body.latitude ?? null,
      body.longitude ?? null,
      bedrooms,
      bathrooms,
      toilets,
      parkingSpaces,
      sizeValue,
      sizeUnit,
      furnished,
      serviced
    )
    .run();

  const propertyId = result.meta.last_row_id;

  const property = await env.DB.prepare(`
    SELECT *
    FROM properties
    WHERE id = ?
  `)
    .bind(propertyId)
    .first();

  return json(
    {
      success: true,
      message: "Property listed successfully.",
      property,
    },
    201
  );
}

async function handleMyProperties(request, env) {
  const auth = await requireUserResponse(request, env);

  if (auth.error) {
    return auth.error;
  }

  const result = await env.DB.prepare(`
    SELECT
      p.*,
      (
        SELECT image_url
        FROM property_images
        WHERE property_id = p.id
        ORDER BY sort_order ASC, id ASC
        LIMIT 1
      ) AS cover_image
    FROM properties p
    WHERE p.user_id = ?
    ORDER BY p.created_at DESC
  `)
    .bind(auth.user.id)
    .all();

  return json({
    success: true,
    properties: result.results || [],
  });
}

async function handleUpdateProperty(
  request,
  env,
  propertyId
) {
  const auth = await requireUserResponse(request, env);

  if (auth.error) {
    return auth.error;
  }

  const property = await env.DB.prepare(`
    SELECT *
    FROM properties
    WHERE id = ?
    LIMIT 1
  `)
    .bind(propertyId)
    .first();

  if (!property) {
    return json(
      {
        success: false,
        message: "Property not found.",
      },
      404
    );
  }

  if (property.user_id !== auth.user.id) {
    return json(
      {
        success: false,
        message: "You cannot edit this property.",
      },
      403
    );
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        success: false,
        message: "Invalid JSON request.",
      },
      400
    );
  }

  const fields = [];
  const values = [];

  const allowedFields = {
    title: "title",
    description: "description",
    listing_type: "listing_type",
    property_type: "property_type",
    price: "price",
    address: "address",
    city: "city",
    state: "state",
    country: "country",
    latitude: "latitude",
    longitude: "longitude",
    bedrooms: "bedrooms",
    bathrooms: "bathrooms",
    toilets: "toilets",
    parking_spaces: "parking_spaces",
    size_value: "size_value",
    size_unit: "size_unit",
    furnished: "furnished",
    serviced: "serviced",
    status: "status",
  };

  for (const [input, column] of Object.entries(
    allowedFields
  )) {
    if (body[input] !== undefined) {
      fields.push(`${column} = ?`);
      values.push(body[input]);
    }
  }

  if (!fields.length) {
    return json({
      success: true,
      message: "Nothing to update.",
    });
  }

  /*
    is_featured and plan_type are deliberately NOT accepted
    from the client.
  */

  fields.push(`updated_at = ?`);
  values.push(now());

  values.push(propertyId);

  await env.DB.prepare(`
    UPDATE properties
    SET ${fields.join(", ")}
    WHERE id = ?
  `)
    .bind(...values)
    .run();

  const updated = await env.DB.prepare(`
    SELECT *
    FROM properties
    WHERE id = ?
  `)
    .bind(propertyId)
    .first();

  return json({
    success: true,
    message: "Property updated successfully.",
    property: updated,
  });
}

async function handleDeleteProperty(
  request,
  env,
  propertyId
) {
  const auth = await requireUserResponse(request, env);

  if (auth.error) {
    return auth.error;
  }

  const property = await env.DB.prepare(`
    SELECT id, user_id
    FROM properties
    WHERE id = ?
    LIMIT 1
  `)
    .bind(propertyId)
    .first();

  if (!property) {
    return json(
      {
        success: false,
        message: "Property not found.",
      },
      404
    );
  }

  if (property.user_id !== auth.user.id) {
    return json(
      {
        success: false,
        message: "You cannot delete this property.",
      },
      403
    );
  }

  const images = await env.DB.prepare(`
    SELECT image_key
    FROM property_images
    WHERE property_id = ?
  `)
    .bind(propertyId)
    .all();

  if (env.PROPERTY_IMAGES && images.results) {
    for (const image of images.results) {
      if (image.image_key) {
        try {
          await env.PROPERTY_IMAGES.delete(
            image.image_key
          );
        } catch {
          // Continue deleting the property even if
          // an individual R2 object is already missing.
        }
      }
    }
  }

  await env.DB.prepare(`
    DELETE FROM properties
    WHERE id = ?
  `)
    .bind(propertyId)
    .run();

  return json({
    success: true,
    message: "Property deleted successfully.",
  });
}

async function handleImageUpload(request, env) {
  const auth = await requireUserResponse(request, env);

  if (auth.error) {
    return auth.error;
  }

  const url = new URL(request.url);
  const propertyId = Number(
    url.searchParams.get("property_id")
  );

  if (!propertyId) {
    return json(
      {
        success: false,
        message: "property_id is required.",
      },
      400
    );
  }

  const property = await env.DB.prepare(`
    SELECT id, user_id
    FROM properties
    WHERE id = ?
    LIMIT 1
  `)
    .bind(propertyId)
    .first();

  if (!property) {
    return json(
      {
        success: false,
        message: "Property not found.",
      },
      404
    );
  }

  if (property.user_id !== auth.user.id) {
    return json(
      {
        success: false,
        message: "You cannot upload images for this property.",
      },
      403
    );
  }

  const existing = await env.DB.prepare(`
    SELECT COUNT(*) AS count
    FROM property_images
    WHERE property_id = ?
  `)
    .bind(propertyId)
    .first();

  const currentCount = Number(existing?.count || 0);

  if (currentCount >= 6) {
    return json(
      {
        success: false,
        message: "A property can have a maximum of 6 images.",
      },
      400
    );
  }

  const form = await request.formData();
  const files = form.getAll("images");

  if (!files.length) {
    return json(
      {
        success: false,
        message: "No images were uploaded.",
      },
      400
    );
  }

  if (currentCount + files.length > 6) {
    return json(
      {
        success: false,
        message: `You can upload only ${
          6 - currentCount
        } more image(s).`,
      },
      400
    );
  }

  const uploaded = [];

  for (let i = 0; i < files.length; i++) {
    const file = files[i];

    if (!(file instanceof File)) {
      continue;
    }

    if (!file.type.startsWith("image/")) {
      continue;
    }

    const extension =
      file.name.split(".").pop()?.toLowerCase() || "jpg";

    const key =
      `properties/${propertyId}/` +
      `${crypto.randomUUID()}.${extension}`;

    await env.PROPERTY_IMAGES.put(
      key,
      file.stream(),
      {
        httpMetadata: {
          contentType: file.type,
        },
      }
    );

    const sortOrder = currentCount + uploaded.length;

    /*
      image_url is left as the storage key for now.
      A public R2/custom-domain URL can be configured later.
    */

    await env.DB.prepare(`
      INSERT INTO property_images (
        property_id,
        image_key,
        image_url,
        sort_order
      )
      VALUES (?, ?, ?, ?)
    `)
      .bind(
        propertyId,
        key,
        key,
        sortOrder
      )
      .run();

    uploaded.push({
      key,
      sort_order: sortOrder,
    });
  }

  return json({
    success: true,
    message: `${uploaded.length} image(s) uploaded successfully.`,
    images: uploaded,
  });
}

async function handleCreateEnquiry(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        success: false,
        message: "Invalid JSON request.",
      },
      400
    );
  }

  const propertyId = Number(body.property_id);
  const name = String(body.name || "").trim();
  const email = body.email
    ? normalizeEmail(body.email)
    : null;
  const phone = String(body.phone || "").trim();
  const message = String(body.message || "").trim();

  if (
    !propertyId ||
    !name ||
    !phone ||
    !message
  ) {
    return json(
      {
        success: false,
        message: "Please complete the enquiry form.",
      },
      400
    );
  }

  const property = await env.DB.prepare(`
    SELECT id
    FROM properties
    WHERE id = ?
      AND status = 'active'
    LIMIT 1
  `)
    .bind(propertyId)
    .first();

  if (!property) {
    return json(
      {
        success: false,
        message: "Property not found.",
      },
      404
    );
  }

  const result = await env.DB.prepare(`
    INSERT INTO enquiries (
      property_id,
      name,
      email,
      phone,
      message
    )
    VALUES (?, ?, ?, ?, ?)
  `)
    .bind(
      propertyId,
      name,
      email,
      phone,
      message
    )
    .run();

  return json(
    {
      success: true,
      message: "Your enquiry has been sent.",
      enquiry_id: result.meta.last_row_id,
    },
    201
  );
}

async function handleFavourite(request, env) {
  const auth = await requireUserResponse(request, env);

  if (auth.error) {
    return auth.error;
  }

  const url = new URL(request.url);
  const propertyId = Number(
    url.searchParams.get("property_id")
  );

  if (!propertyId) {
    return json(
      {
        success: false,
        message: "property_id is required.",
      },
      400
    );
  }

  const property = await env.DB.prepare(`
    SELECT id
    FROM properties
    WHERE id = ?
    LIMIT 1
  `)
    .bind(propertyId)
    .first();

  if (!property) {
    return json(
      {
        success: false,
        message: "Property not found.",
      },
      404
    );
  }

  const existing = await env.DB.prepare(`
    SELECT id
    FROM favourites
    WHERE user_id = ?
      AND property_id = ?
    LIMIT 1
  `)
    .bind(auth.user.id, propertyId)
    .first();

  if (existing) {
    await env.DB.prepare(`
      DELETE FROM favourites
      WHERE id = ?
    `)
      .bind(existing.id)
      .run();

    return json({
      success: true,
      favourited: false,
    });
  }

  await env.DB.prepare(`
    INSERT INTO favourites (
      user_id,
      property_id
    )
    VALUES (?, ?)
  `)
    .bind(auth.user.id, propertyId)
    .run();

  return json({
    success: true,
    favourited: true,
  });
}

async function handleInitializePayment(
  request,
  env
) {
  const auth = await requireUserResponse(request, env);

  if (auth.error) {
    return auth.error;
  }

  if (!env.PAYSTACK_SECRET_KEY) {
    return json(
      {
        success: false,
        message: "Paystack is not configured.",
      },
      500
    );
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        success: false,
        message: "Invalid JSON request.",
      },
      400
    );
  }

  const propertyId = body.property_id
    ? Number(body.property_id)
    : null;

  const listingPlanId = body.listing_plan_id
    ? Number(body.listing_plan_id)
    : null;

  const promotionPlanId = body.promotion_plan_id
    ? Number(body.promotion_plan_id)
    : null;

  let amount = 0;
  let paymentType = null;

  if (listingPlanId) {
    const plan = await env.DB.prepare(`
      SELECT *
      FROM listing_plans
      WHERE id = ?
        AND is_active = 1
      LIMIT 1
    `)
      .bind(listingPlanId)
      .first();

    if (!plan) {
      return json(
        {
          success: false,
          message: "Listing plan not found.",
        },
        404
      );
    }

    amount = Number(plan.price);
    paymentType = "listing";
  }

  if (promotionPlanId) {
    const plan = await env.DB.prepare(`
      SELECT *
      FROM promotion_plans
      WHERE id = ?
        AND is_active = 1
      LIMIT 1
    `)
      .bind(promotionPlanId)
      .first();

    if (!plan) {
      return json(
        {
          success: false,
          message: "Promotion plan not found.",
        },
        404
      );
    }

    amount = Number(plan.price);
    paymentType = "promotion";
  }

  if (!paymentType || amount <= 0) {
    return json(
      {
        success: false,
        message: "A valid paid plan is required.",
      },
      400
    );
  }

  if (propertyId) {
    const property = await env.DB.prepare(`
      SELECT id, user_id
      FROM properties
      WHERE id = ?
      LIMIT 1
    `)
      .bind(propertyId)
      .first();

    if (!property) {
      return json(
        {
          success: false,
          message: "Property not found.",
        },
        404
      );
    }

    if (property.user_id !== auth.user.id) {
      return json(
        {
          success: false,
          message: "You cannot pay for this property.",
        },
        403
      );
    }
  }

  const reference =
    `JOVA_${Date.now()}_${randomToken(8)}`;

  await env.DB.prepare(`
    INSERT INTO payments (
      user_id,
      property_id,
      listing_plan_id,
      promotion_plan_id,
      reference,
      amount,
      currency,
      payment_type,
      status
    )
    VALUES (?, ?, ?, ?, ?, ?, 'NGN', ?, 'pending')
  `)
    .bind(
      auth.user.id,
      propertyId,
      listingPlanId,
      promotionPlanId,
      reference,
      amount,
      paymentType
    )
    .run();

  /*
    Paystack expects amount in kobo.
  */
  const paystackAmount = Math.round(amount * 100);

  const callbackUrl =
    body.callback_url ||
    `${new URL(request.url).origin}/payment-callback.html`;

  const response = await fetch(
    "https://api.paystack.co/transaction/initialize",
    {
      method: "POST",
      headers: {
        Authorization:
          `Bearer ${env.PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email: auth.user.email,
        amount: paystackAmount,
        currency: "NGN",
        reference,
        callback_url: callbackUrl,
        metadata: {
          user_id: auth.user.id,
          property_id: propertyId,
          listing_plan_id: listingPlanId,
          promotion_plan_id: promotionPlanId,
          payment_type: paymentType,
        },
      }),
    }
  );

  const result = await response.json();

  if (!response.ok || !result.status) {
    await env.DB.prepare(`
      UPDATE payments
      SET status = 'failed'
      WHERE reference = ?
    `)
      .bind(reference)
      .run();

    return json(
      {
        success: false,
        message:
          result.message ||
          "Unable to initialize payment.",
      },
      502
    );
  }

  return json({
    success: true,
    reference,
    authorization_url:
      result.data.authorization_url,
    access_code: result.data.access_code,
  });
}

async function handleVerifyPayment(
  request,
  env
) {
  const auth = await requireUserResponse(request, env);

  if (auth.error) {
    return auth.error;
  }

  if (!env.PAYSTACK_SECRET_KEY) {
    return json(
      {
        success: false,
        message: "Paystack is not configured.",
      },
      500
    );
  }

  const url = new URL(request.url);

  let reference =
    url.searchParams.get("reference");

  if (!reference) {
    try {
      const body = await request.json();
      reference = body.reference;
    } catch {
      // Ignore and return validation below.
    }
  }

  if (!reference) {
    return json(
      {
        success: false,
        message: "Payment reference is required.",
      },
      400
    );
  }

  const payment = await env.DB.prepare(`
    SELECT *
    FROM payments
    WHERE reference = ?
      AND user_id = ?
    LIMIT 1
  `)
    .bind(reference, auth.user.id)
    .first();

  if (!payment) {
    return json(
      {
        success: false,
        message: "Payment record not found.",
      },
      404
    );
  }

  if (payment.status === "successful") {
    return json({
      success: true,
      message: "Payment has already been verified.",
      payment,
    });
  }

  const response = await fetch(
    `https://api.paystack.co/transaction/verify/${encodeURIComponent(
      reference
    )}`,
    {
      headers: {
        Authorization:
          `Bearer ${env.PAYSTACK_SECRET_KEY}`,
      },
    }
  );

  const result = await response.json();

  if (
    !response.ok ||
    !result.status ||
    !result.data
  ) {
    return json(
      {
        success: false,
        message:
          result.message ||
          "Unable to verify payment.",
      },
      502
    );
  }

  const transaction = result.data;

  if (transaction.status !== "success") {
    return json(
      {
        success: false,
        message: "Payment has not been completed.",
        status: transaction.status,
      },
      400
    );
  }

  const expectedAmount =
    Math.round(Number(payment.amount) * 100);

  if (
    Number(transaction.amount) !== expectedAmount ||
    String(transaction.currency).toUpperCase() !== "NGN"
  ) {
    return json(
      {
        success: false,
        message: "Payment amount or currency mismatch.",
      },
      400
    );
  }

  await completePayment(
    env,
    payment,
    transaction
  );

  const updated = await env.DB.prepare(`
    SELECT *
    FROM payments
    WHERE id = ?
  `)
    .bind(payment.id)
    .first();

  return json({
    success: true,
    message: "Payment verified successfully.",
    payment: updated,
  });
}

async function completePayment(
  env,
  payment,
  transaction
) {
  /*
    Idempotency:
    If the payment has already been marked successful,
    do nothing.
  */

  const current = await env.DB.prepare(`
    SELECT status
    FROM payments
    WHERE id = ?
    LIMIT 1
  `)
    .bind(payment.id)
    .first();

  if (!current || current.status === "successful") {
    return;
  }

  await env.DB.prepare(`
    UPDATE payments
    SET
      status = 'successful',
      paid_at = ?
    WHERE id = ?
      AND status = 'pending'
  `)
    .bind(
      now(),
      payment.id
    )
    .run();

  if (
    payment.payment_type === "listing" &&
    payment.listing_plan_id
  ) {
    const plan = await env.DB.prepare(`
      SELECT *
      FROM listing_plans
      WHERE id = ?
      LIMIT 1
    `)
      .bind(payment.listing_plan_id)
      .first();

    if (plan) {
      const expires = new Date();

      expires.setDate(
        expires.getDate() +
          Number(plan.duration_days)
      );

      if (payment.property_id) {
        await env.DB.prepare(`
          UPDATE properties
          SET
            plan_type = ?,
            listing_expires_at = ?,
            is_featured = CASE
              WHEN ? = 'featured'
                OR ? = 'premium'
              THEN 1
              ELSE is_featured
            END,
            updated_at = ?
          WHERE id = ?
            AND user_id = ?
        `)
          .bind(
            String(plan.name).toLowerCase(),
            expires.toISOString(),
            String(plan.name).toLowerCase(),
            String(plan.name).toLowerCase(),
            now(),
            payment.property_id,
            payment.user_id
          )
          .run();
      }
    }
  }

  if (
    payment.payment_type === "promotion" &&
    payment.promotion_plan_id &&
    payment.property_id
  ) {
    const plan = await env.DB.prepare(`
      SELECT *
      FROM promotion_plans
      WHERE id = ?
      LIMIT 1
    `)
      .bind(payment.promotion_plan_id)
      .first();

    const property = await env.DB.prepare(`
      SELECT id, user_id
      FROM properties
      WHERE id = ?
      LIMIT 1
    `)
      .bind(payment.property_id)
      .first();

    if (plan && property) {
      const startsAt = new Date();
      const expiresAt = new Date();

      expiresAt.setDate(
        expiresAt.getDate() +
          Number(plan.duration_days)
      );

      await env.DB.prepare(`
        INSERT INTO property_promotions (
          property_id,
          promotion_plan_id,
          starts_at,
          expires_at,
          status
        )
        VALUES (?, ?, ?, ?, 'active')
      `)
        .bind(
          property.id,
          plan.id,
          startsAt.toISOString(),
          expiresAt.toISOString()
        )
        .run();

      await env.DB.prepare(`
        UPDATE properties
        SET
          is_featured = 1,
          updated_at = ?
        WHERE id = ?
      `)
        .bind(
          now(),
          property.id
        )
        .run();
    }
  }
}

async function handlePaystackWebhook(
  request,
  env
) {
  if (!env.PAYSTACK_SECRET_KEY) {
    return text(
      "Paystack is not configured.",
      500
    );
  }

  const signature =
    request.headers.get("x-paystack-signature");

  if (!signature) {
    return text("Missing signature.", 401);
  }

  const rawBody = await request.text();

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(
      env.PAYSTACK_SECRET_KEY
    ),
    {
      name: "HMAC",
      hash: "SHA-512",
    },
    false,
    ["sign"]
  );

  const signatureBytes =
    await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(rawBody)
    );

  const calculated = [...new Uint8Array(signatureBytes)]
    .map((b) =>
      b.toString(16).padStart(2, "0")
    )
    .join("");

  if (
    calculated.toLowerCase() !==
    signature.toLowerCase()
  ) {
    return text("Invalid signature.", 401);
  }

  let event;

  try {
    event = JSON.parse(rawBody);
  } catch {
    return text("Invalid JSON.", 400);
  }

  if (event.event !== "charge.success") {
    return text("Event ignored.", 200);
  }

  const transaction = event.data;

  if (!transaction?.reference) {
    return text("Missing reference.", 400);
  }

  const payment = await env.DB.prepare(`
    SELECT *
    FROM payments
    WHERE reference = ?
    LIMIT 1
  `)
    .bind(transaction.reference)
    .first();

  if (!payment) {
    return text("Payment not found.", 404);
  }

  const expectedAmount =
    Math.round(Number(payment.amount) * 100);

  if (
    Number(transaction.amount) !== expectedAmount ||
    String(transaction.currency).toUpperCase() !== "NGN"
  ) {
    return text("Payment mismatch.", 400);
  }

  await completePayment(
    env,
    payment,
    transaction
  );

  return text("OK", 200);
}

async function handleHealth(env) {
  let database = false;

  try {
    await env.DB.prepare(`
      SELECT 1
    `).first();

    database = true;
  } catch {
    database = false;
  }

  return json({
    success: true,
    service: "JOVA Property Marketplace API",
    status: "online",
    database,
    r2: Boolean(env.PROPERTY_IMAGES),
    payments: Boolean(env.PAYSTACK_SECRET_KEY),
    timestamp: now(),
  });
}

async function routeApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: CORS_HEADERS,
    });
  }

  if (
    path === "/api/health" ||
    path === "/health"
  ) {
    return handleHealth(env);
  }

  if (
    path === "/api/auth/register" &&
    method === "POST"
  ) {
    return handleRegister(request, env);
  }

  if (
    path === "/api/auth/login" &&
    method === "POST"
  ) {
    return handleLogin(request, env);
  }

  if (
    path === "/api/auth/logout" &&
    method === "POST"
  ) {
    return handleLogout(request, env);
  }

  if (
    path === "/api/auth/me" &&
    method === "GET"
  ) {
    return handleMe(request, env);
  }

  if (
    path === "/api/listing-plans" &&
    method === "GET"
  ) {
    return handlePlans(env);
  }

  if (
    path === "/api/subscription-plans" &&
    method === "GET"
  ) {
    return handlePlans(env);
  }

  if (
    path === "/api/properties" &&
    method === "GET"
  ) {
    return handleGetProperties(
      request,
      env
    );
  }

  if (
    path === "/api/properties" &&
    method === "POST"
  ) {
    return handleCreateProperty(
      request,
      env
    );
  }

  if (
    path === "/api/my-properties" &&
    method === "GET"
  ) {
    return handleMyProperties(
      request,
      env
    );
  }

  if (
    path === "/api/property-images" &&
    method === "POST"
  ) {
    return handleImageUpload(
      request,
      env
    );
  }

  if (
    path === "/api/enquiries" &&
    method === "POST"
  ) {
    return handleCreateEnquiry(
      request,
      env
    );
  }

  if (
    path === "/api/favourites" &&
    method === "POST"
  ) {
    return handleFavourite(
      request,
      env
    );
  }

  if (
    path === "/api/payments/initialize" &&
    method === "POST"
  ) {
    return handleInitializePayment(
      request,
      env
    );
  }

  if (
    path === "/api/payments/verify" &&
    (method === "GET" || method === "POST")
  ) {
    return handleVerifyPayment(
      request,
      env
    );
  }

  if (
    path === "/api/payments/webhook" &&
    method === "POST"
  ) {
    return handlePaystackWebhook(
      request,
      env
    );
  }

  const propertyMatch =
    path.match(/^\/api\/properties\/(\d+)$/);

  if (propertyMatch) {
    const propertyId = Number(
      propertyMatch[1]
    );

    if (method === "GET") {
      return handleGetProperty(
        request,
        env,
        propertyId
      );
    }

    if (method === "PATCH") {
      return handleUpdateProperty(
        request,
        env,
        propertyId
      );
    }

    if (method === "DELETE") {
      return handleDeleteProperty(
        request,
        env,
        propertyId
      );
    }
  }

  return json(
    {
      success: false,
      message: "API route not found.",
    },
    404
  );
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    /*
      API requests are handled by the Worker.
    */
    if (url.pathname.startsWith("/api/")) {
      try {
        return await routeApi(
          request,
          env
        );
      } catch (error) {
        console.error(
          "API ERROR:",
          error
        );

        return json(
          {
            success: false,
            message:
              "An internal server error occurred.",
          },
          500
        );
      }
    }

    /*
      Everything else is served by Cloudflare Assets.
      This requires wrangler.jsonc to point to the
      correct frontend directory.
    */
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return text(
      "JOVA Property Marketplace",
      200,
      "text/plain; charset=utf-8"
    );
  },
};
