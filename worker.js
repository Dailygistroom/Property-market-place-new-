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
    headers: { ...CORS, ...headers }
  });

const now = () => new Date().toISOString();

function randomHex(bytes = 32) {
  const values = crypto.getRandomValues(new Uint8Array(bytes));

  return [...values]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function randomReferralCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let result = "PM";

  const values =
    crypto.getRandomValues(
      new Uint8Array(6)
    );

  for (let i = 0; i < 6; i++) {
    result +=
      chars[values[i] % chars.length];
  }

  return result;
}

function getToken(request) {
  return (
    request.headers.get("Authorization") || ""
  )
    .replace(/^Bearer\s+/i, "")
    .trim();
}

/* =========================================================
   DATABASE
========================================================= */

async function ensureDatabase(env) {
  await env.DB.batch([
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS subscription_plans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        amount INTEGER NOT NULL,
        currency TEXT NOT NULL DEFAULT 'NGN',
        billing_cycle TEXT NOT NULL DEFAULT 'monthly',
        listing_limit INTEGER NOT NULL,
        boost_credits INTEGER NOT NULL DEFAULT 0,
        unlimited_boost INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'active',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `),

    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        plan_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        start_at TEXT,
        end_at TEXT,
        listing_limit INTEGER NOT NULL DEFAULT 0,
        boost_credits_allocated INTEGER NOT NULL DEFAULT 0,
        boost_credits_remaining INTEGER NOT NULL DEFAULT 0,
        unlimited_boost INTEGER NOT NULL DEFAULT 0,
        payment_reference TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `),

    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS referrals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        referrer_user_id INTEGER NOT NULL,
        referred_user_id INTEGER NOT NULL,
        referral_code TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        reward_credits INTEGER NOT NULL DEFAULT 3,
        rewarded_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `),

    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS boost_transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        property_id INTEGER,
        type TEXT NOT NULL,
        credits INTEGER NOT NULL,
        description TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `),

    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS marketplace_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        phone TEXT,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        referral_code TEXT UNIQUE,
        referred_by_code TEXT,
        boost_credits INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `),

    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS marketplace_sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      )
    `),

    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS property_owners (
        property_id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `),

    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS property_boosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        property_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        start_at TEXT NOT NULL,
        end_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `)
  ]);

  const plans = [
    ["Starter", 1500000, 25, 5, 0],
    ["Professional", 2500000, 40, 10, 0],
    ["Business", 3500000, 55, 17, 0],
    ["Premium", 5000000, 70, 25, 0],
    ["Growth", 7000000, 100, 0, 1],
    ["Enterprise", 10000000, 150, 0, 1]
  ];

  for (const [
    name,
    amount,
    listingLimit,
    boostCredits,
    unlimitedBoost
  ] of plans) {
    await env.DB.prepare(`
      INSERT OR IGNORE INTO subscription_plans
      (
        name,
        amount,
        currency,
        billing_cycle,
        listing_limit,
        boost_credits,
        unlimited_boost,
        status
      )
      VALUES (?, ?, 'NGN', 'monthly', ?, ?, ?, 'active')
    `).bind(
      name,
      amount,
      listingLimit,
      boostCredits,
      unlimitedBoost
    ).run();
  }
}

/* =========================================================
   PASSWORDS
========================================================= */

async function hashPassword(password) {
  const salt =
    crypto.getRandomValues(
      new Uint8Array(16)
    );

  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256"
      },
      key,
      256
    );

  const toBase64 = value =>
    btoa(
      String.fromCharCode(
        ...new Uint8Array(value)
      )
    );

  return `${toBase64(salt)}.${toBase64(bits)}`;
}

async function verifyPassword(
  password,
  stored
) {
  try {
    const [
      saltString,
      hashString
    ] = stored.split(".");

    const salt =
      Uint8Array.from(
        atob(saltString),
        c => c.charCodeAt(0)
      );

    const expected =
      Uint8Array.from(
        atob(hashString),
        c => c.charCodeAt(0)
      );

    const key =
      await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveBits"]
      );

    const bits =
      new Uint8Array(
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

    if (
      bits.length !==
      expected.length
    ) {
      return false;
    }

    return bits.every(
      (value, index) =>
        value === expected[index]
    );
  } catch {
    return false;
  }
}

/* =========================================================
   AUTH
========================================================= */

async function getCurrentUser(
  request,
  env
) {
  const token =
    getToken(request);

  if (!token) return null;

  return await env.DB.prepare(`
    SELECT u.*
    FROM marketplace_sessions s
    JOIN marketplace_users u
      ON u.id = s.user_id
    WHERE s.id = ?
      AND s.expires_at > ?
      AND u.status = 'active'
  `).bind(
    token,
    now()
  ).first();
}

function publicUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    full_name: user.full_name,
    email: user.email,
    phone: user.phone,
    role: user.role,
    referral_code:
      user.referral_code,
    boost_credits:
      user.boost_credits
  };
}

async function register(
  request,
  env
) {
  const data =
    await request.json();

  const fullName =
    String(
      data.full_name ||
      data.name ||
      ""
    ).trim();

  const email =
    String(
      data.email || ""
    )
      .trim()
      .toLowerCase();

  const phone =
    String(
      data.phone || ""
    ).trim();

  const password =
    String(
      data.password || ""
    );

  const role =
    String(
      data.role || ""
    )
      .trim()
      .toLowerCase();

  const referralCode =
    String(
      data.referral_code ||
      data.referralCode ||
      ""
    )
      .trim()
      .toUpperCase();

  if (
    !fullName ||
    !email ||
    !password ||
    !role
  ) {
    return json({
      success: false,
      error:
        "Full name, email, password and role are required."
    }, 400);
  }

  if (
    ![
      "agent",
      "landlord",
      "developer"
    ].includes(role)
  ) {
    return json({
      success: false,
      error:
        "Role must be agent, landlord or developer."
    }, 400);
  }

  if (password.length < 8) {
    return json({
      success: false,
      error:
        "Password must be at least 8 characters."
    }, 400);
  }

  const existing =
    await env.DB.prepare(
      "SELECT id FROM marketplace_users WHERE email = ?"
    ).bind(email).first();

  if (existing) {
    return json({
      success: false,
      error:
        "An account with this email already exists."
    }, 409);
  }

  let referrer = null;

  if (referralCode) {
    referrer =
      await env.DB.prepare(`
        SELECT id, role
        FROM marketplace_users
        WHERE referral_code = ?
          AND status = 'active'
      `).bind(
        referralCode
      ).first();

    if (!referrer) {
      return json({
        success: false,
        error:
          "Invalid referral code."
      }, 400);
    }

    if (
      referrer.role !== "agent" &&
      referrer.role !== "landlord"
    ) {
      return json({
        success: false,
        error:
          "This referral code is not eligible."
      }, 400);
    }
  }

  const passwordHash =
    await hashPassword(
      password
    );

  const result =
    await env.DB.prepare(`
      INSERT INTO marketplace_users
      (
        full_name,
        email,
        phone,
        password_hash,
        role,
        status,
        referred_by_code,
        boost_credits
      )
      VALUES (?, ?, ?, ?, ?, 'active', ?, 0)
    `).bind(
      fullName,
      email,
      phone || null,
      passwordHash,
      role,
      referralCode || null
    ).run();

  const userId =
    result.meta.last_row_id;

  if (referrer) {
    await env.DB.prepare(`
      INSERT INTO referrals
      (
        referrer_user_id,
        referred_user_id,
        referral_code,
        status,
        reward_credits
      )
      VALUES (?, ?, ?, 'pending', 3)
    `).bind(
      referrer.id,
      userId,
      referralCode
    ).run();
  }

  const user =
    await env.DB.prepare(
      "SELECT * FROM marketplace_users WHERE id = ?"
    ).bind(userId).first();

  return json({
    success: true,
    message:
      "Account created successfully.",
    user:
      publicUser(user)
  }, 201);
}

async function login(
  request,
  env
) {
  const data =
    await request.json();

  const email =
    String(
      data.email || ""
    )
      .trim()
      .toLowerCase();

  const password =
    String(
      data.password || ""
    );

  const user =
    await env.DB.prepare(`
      SELECT *
      FROM marketplace_users
      WHERE email = ?
        AND status = 'active'
    `).bind(email).first();

  if (
    !user ||
    !(await verifyPassword(
      password,
      user.password_hash
    ))
  ) {
    return json({
      success: false,
      error:
        "Invalid email or password."
    }, 401);
  }

  const token =
    randomHex(32);

  const createdAt =
    now();

  const expiresAt =
    new Date(
      Date.now() +
      30 *
      24 *
      60 *
      60 *
      1000
    ).toISOString();

  await env.DB.prepare(`
    INSERT INTO marketplace_sessions
    (
      id,
      user_id,
      created_at,
      expires_at
    )
    VALUES (?, ?, ?, ?)
  `).bind(
    token,
    user.id,
    createdAt,
    expiresAt
  ).run();

  return json({
    success: true,
    token,
    user:
      publicUser(user)
  });
}

async function logout(
  request,
  env
) {
  const token =
    getToken(request);

  if (token) {
    await env.DB.prepare(
      "DELETE FROM marketplace_sessions WHERE id = ?"
    ).bind(token).run();
  }

  return json({
    success: true
  });
}

/* =========================================================
   SUBSCRIPTION PLANS
========================================================= */

async function getPlans(env) {
  const result =
    await env.DB.prepare(`
      SELECT
        id,
        name,
        amount,
        currency,
        billing_cycle,
        listing_limit,
        boost_credits,
        unlimited_boost,
        status
      FROM subscription_plans
      WHERE status = 'active'
      ORDER BY amount ASC
    `).all();

  return json({
    success: true,
    plans:
      result.results || []
  });
}

/* =========================================================
   CURRENT SUBSCRIPTION
========================================================= */

async function getActiveSubscription(
  userId,
  env
) {
  return await env.DB.prepare(`
    SELECT
      s.*,
      p.name AS plan_name,
      p.amount AS plan_amount,
      p.currency,
      p.billing_cycle
    FROM subscriptions s
    JOIN subscription_plans p
      ON p.id = s.plan_id
    WHERE s.user_id = ?
      AND s.status = 'active'
      AND s.end_at > ?
    ORDER BY s.id DESC
    LIMIT 1
  `).bind(
    userId,
    now()
  ).first();
}

/* =========================================================
   PAYSTACK
========================================================= */

async function paystackRequest(
  env,
  path,
  options = {}
) {
  if (
    !env.PAYSTACK_SECRET_KEY
  ) {
    throw new Error(
      "PAYSTACK_SECRET_KEY is not configured."
    );
  }

  const response =
    await fetch(
      `https://api.paystack.co${path}`,
      {
        ...options,
        headers: {
          Authorization:
            `Bearer ${env.PAYSTACK_SECRET_KEY}`,
          "Content-Type":
            "application/json",
          ...(options.headers || {})
        }
      }
    );

  const data =
    await response.json();

  if (
    !response.ok ||
    data.status === false
  ) {
    throw new Error(
      data.message ||
      "Paystack request failed."
    );
  }

  return data;
}

function createPaymentReference() {
  return `JOVA-${Date.now()}-${randomHex(6)}`;
}

/* =========================================================
   PAYMENT INITIALIZATION
========================================================= */

async function initializePayment(
  request,
  env
) {
  const user =
    await getCurrentUser(
      request,
      env
    );

  if (!user) {
    return json({
      success: false,
      error:
        "Sign in required."
    }, 401);
  }

  if (
    user.role !== "agent" &&
    user.role !== "landlord" &&
    user.role !== "developer"
  ) {
    return json({
      success: false,
      error:
        "Only property advertisers can subscribe."
    }, 403);
  }

  const data =
    await request.json();

  const planId =
    Number(data.plan_id);

  if (!planId) {
    return json({
      success: false,
      error:
        "A subscription plan is required."
    }, 400);
  }

  const plan =
    await env.DB.prepare(`
      SELECT *
      FROM subscription_plans
      WHERE id = ?
        AND status = 'active'
    `).bind(planId).first();

  if (!plan) {
    return json({
      success: false,
      error:
        "Subscription plan not found."
    }, 404);
  }

  const reference =
    createPaymentReference();

  const callbackUrl =
    data.callback_url ||
    env.PAYSTACK_CALLBACK_URL ||
    new URL(request.url).origin;

  await env.DB.prepare(`
    INSERT INTO payment_transactions
    (
      user_id,
      plan_id,
      plan_name,
      amount,
      currency,
      reference,
      status,
      gateway,
      metadata
    )
    VALUES (?, ?, ?, ?, 'NGN', ?, 'pending', 'paystack', ?)
  `).bind(
    user.id,
    plan.id,
    plan.name,
    plan.amount,
    reference,
    JSON.stringify({
      user_id: user.id,
      plan_id: plan.id,
      plan_name: plan.name
    })
  ).run();

  try {
    const payment =
      await paystackRequest(
        env,
        "/transaction/initialize",
        {
          method: "POST",
          body: JSON.stringify({
            email: user.email,
            amount: plan.amount,
            reference,
            callback_url:
              callbackUrl,
            metadata: {
              user_id: user.id,
              plan_id: plan.id,
              plan_name:
                plan.name,
              product:
                "JOVA Subscription"
            }
          })
        }
      );

    return json({
      success: true,
      reference,
      authorization_url:
        payment.data.authorization_url,
      access_code:
        payment.data.access_code
    });
  } catch (error) {
    await env.DB.prepare(`
      UPDATE payment_transactions
      SET
        status = 'failed',
        gateway_response = ?,
        updated_at = ?
      WHERE reference = ?
    `).bind(
      error.message,
      now(),
      reference
    ).run();

    return json({
      success: false,
      error:
        error.message
    }, 500);
  }
}

/* =========================================================
   SUBSCRIPTION ACTIVATION
========================================================= */

async function activateSubscription(
  env,
  payment,
  plan
) {
  const existing =
    await env.DB.prepare(`
      SELECT id
      FROM subscriptions
      WHERE payment_reference = ?
    `).bind(
      payment.reference
    ).first();

  if (existing) return;

  const start =
    new Date();

  const end =
    new Date(start);

  end.setMonth(
    end.getMonth() + 1
  );

  await env.DB.prepare(`
    UPDATE subscriptions
    SET
      status = 'expired',
      updated_at = ?
    WHERE user_id = ?
      AND status = 'active'
  `).bind(
    now(),
    payment.user_id
  ).run();

  await env.DB.prepare(`
    INSERT INTO subscriptions
    (
      user_id,
      plan_id,
      status,
      start_at,
      end_at,
      listing_limit,
      boost_credits_allocated,
      boost_credits_remaining,
      unlimited_boost,
      payment_reference
    )
    VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    payment.user_id,
    plan.id,
    "active",
    start.toISOString(),
    end.toISOString(),
    plan.listing_limit,
    plan.boost_credits,
    plan.boost_credits,
    plan.unlimited_boost,
    payment.reference
  ).run();

  await env.DB.prepare(`
    UPDATE marketplace_users
    SET
      boost_credits = ?,
      updated_at = ?
    WHERE id = ?
  `).bind(
    plan.boost_credits,
    now(),
    payment.user_id
  ).run();

  const user =
    await env.DB.prepare(`
      SELECT role, referral_code
      FROM marketplace_users
      WHERE id = ?
    `).bind(
      payment.user_id
    ).first();

  if (
    user &&
    (
      user.role === "agent" ||
      user.role === "landlord"
    ) &&
    !user.referral_code
  ) {
    let code;
    let exists = true;

    while (exists) {
      code =
        randomReferralCode();

      exists =
        await env.DB.prepare(`
          SELECT id
          FROM marketplace_users
          WHERE referral_code = ?
        `).bind(code).first();
    }

    await env.DB.prepare(`
      UPDATE marketplace_users
      SET
        referral_code = ?,
        updated_at = ?
      WHERE id = ?
    `).bind(
      code,
      now(),
      payment.user_id
    ).run();
  }

  const referral =
    await env.DB.prepare(`
      SELECT *
      FROM referrals
      WHERE referred_user_id = ?
        AND status = 'pending'
      ORDER BY id DESC
      LIMIT 1
    `).bind(
      payment.user_id
    ).first();

  if (referral) {
    await env.DB.prepare(`
      UPDATE marketplace_users
      SET
        boost_credits =
          boost_credits + ?,
        updated_at = ?
      WHERE id = ?
    `).bind(
      referral.reward_credits,
      now(),
      referral.referrer_user_id
    ).run();

    await env.DB.prepare(`
      UPDATE referrals
      SET
        status = 'qualified',
        rewarded_at = ?,
        updated_at = ?
      WHERE id = ?
        AND status = 'pending'
    `).bind(
      now(),
      now(),
      referral.id
    ).run();

    await env.DB.prepare(`
      INSERT INTO boost_transactions
      (
        user_id,
        type,
        credits,
        description
      )
      VALUES (?, 'referral_reward', ?, ?)
    `).bind(
      referral.referrer_user_id,
      referral.reward_credits,
      "Referral reward for a successful JOVA subscription"
    ).run();
  }
}

/* =========================================================
   PAYMENT VERIFICATION
========================================================= */

async function verifyPayment(
  request,
  env
) {
  const user =
    await getCurrentUser(
      request,
      env
    );

  if (!user) {
    return json({
      success: false,
      error:
        "Sign in required."
    }, 401);
  }

  const url =
    new URL(request.url);

  const reference =
    url.searchParams.get(
      "reference"
    ) ||
    url.searchParams.get(
      "trxref"
    );

  if (!reference) {
    return json({
      success: false,
      error:
        "Payment reference is required."
    }, 400);
  }

  const payment =
    await env.DB.prepare(`
      SELECT *
      FROM payment_transactions
      WHERE reference = ?
        AND user_id = ?
    `).bind(
      reference,
      user.id
    ).first();

  if (!payment) {
    return json({
      success: false,
      error:
        "Payment transaction not found."
    }, 404);
  }

  const result =
    await paystackRequest(
      env,
      `/transaction/verify/${encodeURIComponent(reference)}`
    );

  const transaction =
    result.data;

  const successful =
    transaction.status === "success" &&
    transaction.currency === "NGN";

  if (!successful) {
    await env.DB.prepare(`
      UPDATE payment_transactions
      SET
        status = 'failed',
        gateway_response = ?,
        updated_at = ?
      WHERE reference = ?
    `).bind(
      JSON.stringify(transaction),
      now(),
      reference
    ).run();

    return json({
      success: false,
      status:
        transaction.status,
      message:
        "Payment has not been completed."
    });
  }

  if (
    Number(transaction.amount) !==
    Number(payment.amount)
  ) {
    return json({
      success: false,
      error:
        "Payment amount does not match the subscription."
    }, 400);
  }

  const plan =
    await env.DB.prepare(`
      SELECT *
      FROM subscription_plans
      WHERE id = ?
    `).bind(
      payment.plan_id
    ).first();

  if (!plan) {
    return json({
      success: false,
      error:
        "Subscription plan no longer exists."
    }, 500);
  }

  await env.DB.prepare(`
    UPDATE payment_transactions
    SET
      status = 'success',
      paid_at = ?,
      gateway_response = ?,
      updated_at = ?
    WHERE reference = ?
  `).bind(
    now(),
    JSON.stringify(transaction),
    now(),
    reference
  ).run();

  await activateSubscription(
    env,
    payment,
    plan
  );

  const subscription =
    await env.DB.prepare(`
      SELECT *
      FROM subscriptions
      WHERE payment_reference = ?
      ORDER BY id DESC
      LIMIT 1
    `).bind(
      reference
    ).first();

  const updatedUser =
    await env.DB.prepare(`
      SELECT *
      FROM marketplace_users
      WHERE id = ?
    `).bind(
      user.id
    ).first();

  return json({
    success: true,
    message:
      "Payment verified and subscription activated.",
    payment: {
      reference,
      status:
        "success",
      amount:
        payment.amount,
      currency:
        payment.currency
    },
    subscription,
    user:
      publicUser(updatedUser)
  });
}

/* =========================================================
   PAYSTACK WEBHOOK
========================================================= */

async function verifyPaystackSignature(
  request,
  env,
  rawBody
) {
  if (!env.PAYSTACK_SECRET_KEY) {
    return false;
  }

  const signature =
    request.headers.get(
      "x-paystack-signature"
    ) || "";

  if (!signature) {
    return false;
  }

  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(
        env.PAYSTACK_SECRET_KEY
      ),
      {
        name: "HMAC",
        hash: "SHA-512"
      },
      false,
      ["sign"]
    );

  const signed =
    await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(
        rawBody
      )
    );

  const calculated =
    [...new Uint8Array(signed)]
      .map(x =>
        x.toString(16)
          .padStart(2, "0")
      )
      .join("");

  return calculated === signature;
}

async function paystackWebhook(
  request,
  env
) {
  const rawBody =
    await request.text();

  const valid =
    await verifyPaystackSignature(
      request,
      env,
      rawBody
    );

  if (!valid) {
    return json({
      success: false,
      error:
        "Invalid webhook signature."
    }, 401);
  }

  const event =
    JSON.parse(rawBody);

  if (
    event.event !==
    "charge.success"
  ) {
    return json({
      success: true
    });
  }

  const transaction =
    event.data;

  const payment =
    await env.DB.prepare(`
      SELECT *
      FROM payment_transactions
      WHERE reference = ?
    `).bind(
      transaction.reference
    ).first();

  if (!payment) {
    return json({
      success: true
    });
  }

  if (
    payment.status ===
    "success"
  ) {
    return json({
      success: true
    });
  }

  if (
    Number(transaction.amount) !==
    Number(payment.amount)
  ) {
    return json({
      success: false,
      error:
        "Payment amount does not match."
    }, 400);
  }

  const plan =
    await env.DB.prepare(`
      SELECT *
      FROM subscription_plans
      WHERE id = ?
    `).bind(
      payment.plan_id
    ).first();

  if (!plan) {
    return json({
      success: false,
      error:
        "Plan not found."
    }, 500);
  }

  await env.DB.prepare(`
    UPDATE payment_transactions
    SET
      status = 'success',
      paid_at = ?,
      gateway_response = ?,
      updated_at = ?
    WHERE reference = ?
  `).bind(
    now(),
    JSON.stringify(transaction),
    now(),
    transaction.reference
  ).run();

  await activateSubscription(
    env,
    payment,
    plan
  );

  return json({
    success: true
  });
}

/* =========================================================
   CURRENT SUBSCRIPTION
========================================================= */

async function currentSubscription(
  request,
  env
) {
  const user =
    await getCurrentUser(
      request,
      env
    );

  if (!user) {
    return json({
      success: false,
      error:
        "Sign in required."
    }, 401);
  }

  const subscription =
    await getActiveSubscription(
      user.id,
      env
    );

  return json({
    success: true,
    subscription:
      subscription || null
  });
}

/* =========================================================
   REFERRALS
========================================================= */

async function referralDashboard(
  request,
  env
) {
  const user =
    await getCurrentUser(
      request,
      env
    );

  if (!user) {
    return json({
      success: false,
      error:
        "Sign in required."
    }, 401);
  }

  const referrals =
    await env.DB.prepare(`
      SELECT
        r.id,
        r.referral_code,
        r.status,
        r.reward_credits,
        r.rewarded_at,
        r.created_at,
        u.full_name,
        u.email
      FROM referrals r
      JOIN marketplace_users u
        ON u.id = r.referred_user_id
      WHERE r.referrer_user_id = ?
      ORDER BY r.created_at DESC
    `).bind(
      user.id
    ).all();

  const list =
    referrals.results || [];

  const successful =
    list.filter(
      x =>
        x.status ===
        "qualified"
    ).length;

  const earned =
    list
      .filter(
        x =>
          x.status ===
          "qualified"
      )
      .reduce(
        (sum, x) =>
          sum +
          Number(
            x.reward_credits || 0
          ),
        0
      );

  return json({
    success: true,
    referral_code:
      user.referral_code ||
      null,
    referral_link:
      user.referral_code
        ? `/register?ref=${user.referral_code}`
        : null,
    people_referred:
      list.length,
    successful_subscriptions:
      successful,
    boost_credits_earned:
      earned,
    boost_credits_balance:
      user.boost_credits,
    referrals:
      list
  });
}

/* =========================================================
   LISTING ELIGIBILITY
========================================================= */

async function checkListingEligibility(
  user,
  env
) {
  const subscription =
    await getActiveSubscription(
      user.id,
      env
    );

  if (!subscription) {
    return {
      allowed: false,
      response: json({
        success: false,
        error:
          "An active JOVA subscription is required before you can publish properties."
      }, 403)
    };
  }

  const countResult =
    await env.DB.prepare(`
      SELECT COUNT(*) AS total
      FROM property_owners
      WHERE user_id = ?
    `).bind(
      user.id
    ).first();

  const currentCount =
    Number(
      countResult?.total || 0
    );

  if (
    currentCount >=
    Number(
      subscription.listing_limit
    )
  ) {
    return {
      allowed: false,
      response: json({
        success: false,
        error:
          `Your ${subscription.plan_name} plan allows up to ${subscription.listing_limit} properties.`,
        listing_limit:
          subscription.listing_limit,
        current_listings:
          currentCount
      }, 403)
    };
  }

  return {
    allowed: true,
    subscription,
    currentCount
  };
}

/* =========================================================
   PROPERTY API
========================================================= */

async function getProperties(
  request,
  env,
  url
) {
  let sql = `
    SELECT
      p.*,
      po.user_id AS owner_user_id,
      mu.full_name AS advertiser_name,
      mu.role AS advertiser_role,
      pb.id AS active_boost_id,
      pb.start_at AS boost_start_at,
      pb.end_at AS boost_end_at
    FROM properties p
    LEFT JOIN property_owners po
      ON po.property_id = p.id
    LEFT JOIN marketplace_users mu
      ON mu.id = po.user_id
    LEFT JOIN property_boosts pb
      ON pb.property_id = p.id
      AND pb.status = 'active'
      AND pb.end_at > ?
    WHERE 1 = 1
  `;

  const values = [
    now()
  ];

  const location =
    url.searchParams.get(
      "location"
    );

  const purpose =
    url.searchParams.get(
      "purpose"
    );

  const propertyType =
    url.searchParams.get(
      "property_type"
    );

  const maxPrice =
    url.searchParams.get(
      "max_price"
    );

  const bedrooms =
    url.searchParams.get(
      "bedrooms"
    );

  if (location) {
    sql +=
      " AND p.location LIKE ?";

    values.push(
      `%${location}%`
    );
  }

  if (purpose) {
    sql +=
      " AND p.status = ?";

    values.push(
      purpose
    );
  }

  if (propertyType) {
    sql +=
      " AND p.property_type = ?";

    values.push(
      propertyType
    );
  }

  if (maxPrice) {
    sql +=
      " AND p.price <= ?";

    values.push(
      Number(maxPrice)
    );
  }

  if (bedrooms) {
    sql +=
      " AND p.bedrooms >= ?";

    values.push(
      Number(bedrooms)
    );
  }

  sql += `
    ORDER BY
      CASE
        WHEN pb.id IS NOT NULL
        THEN 0
        ELSE 1
      END,
      p.created_at DESC
    LIMIT 100
  `;

  const result =
    await env.DB
      .prepare(sql)
      .bind(...values)
      .all();

  return json({
    success: true,
    properties:
      result.results || []
  });
}

/* =========================================================
   CREATE PROPERTY
========================================================= */

async function createProperty(
  request,
  env
) {
  const user =
    await getCurrentUser(
      request,
      env
    );

  if (!user) {
    return json({
      success: false,
      error:
        "Sign in required to publish a property."
    }, 401);
  }

  if (
    user.role !== "agent" &&
    user.role !== "landlord" &&
    user.role !== "developer"
  ) {
    return json({
      success: false,
      error:
        "Only agents, landlords and developers can publish properties."
    }, 403);
  }

  const eligibility =
    await checkListingEligibility(
      user,
      env
    );

  if (!eligibility.allowed) {
    return eligibility.response;
  }

  const data =
    await request.json();

  const title =
    String(
      data.title || ""
    ).trim();

  const description =
    String(
      data.description || ""
    ).trim();

  const category =
    String(
      data.category || ""
    ).trim();

  const propertyType =
    String(
      data.property_type || ""
    ).trim();

  const price =
    Number(
      data.price || 0
    );

  const location =
    String(
      data.location || ""
    ).trim();

  if (
    !title ||
    !propertyType ||
    !location ||
    price <= 0
  ) {
    return json({
      success: false,
      error:
        "Title, property type, location and price are required."
    }, 400);
  }

  const result =
    await env.DB.prepare(`
      INSERT INTO properties
      (
        title,
        description,
        category,
        property_type,
        price,
        location,
        bedrooms,
        bathrooms,
        area,
        amenities,
        status,
        featured,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      title,
      description,
      category,
      propertyType,
      price,
      location,
      Number(
        data.bedrooms || 0
      ),
      Number(
        data.bathrooms || 0
      ),
      Number(
        data.area || 0
      ),
      JSON.stringify(
        data.amenities || []
      ),
      String(
        data.status ||
        "available"
      ),
      Number(
        data.featured || 0
      ),
      now(),
      now()
    ).run();

  const propertyId =
    result.meta.last_row_id;

  await env.DB.prepare(`
    INSERT INTO property_owners
    (
      property_id,
      user_id
    )
    VALUES (?, ?)
  `).bind(
    propertyId,
    user.id
  ).run();

  return json({
    success: true,
    message:
      "Property published successfully.",
    property_id:
      propertyId,
    listing_limit:
      eligibility
        .subscription
        .listing_limit,
    listings_used:
      eligibility.currentCount + 1
  }, 201);
}

/* =========================================================
   MY PROPERTIES
========================================================= */

async function myProperties(
  request,
  env
) {
  const user =
    await getCurrentUser(
      request,
      env
    );

  if (!user) {
    return json({
      success: false,
      error:
        "Sign in required."
    }, 401);
  }

  const result =
    await env.DB.prepare(`
      SELECT
        p.*,
        pb.id AS active_boost_id,
        pb.start_at AS boost_start_at,
        pb.end_at AS boost_end_at
      FROM properties p
      JOIN property_owners po
        ON po.property_id = p.id
      LEFT JOIN property_boosts pb
        ON pb.property_id = p.id
        AND pb.status = 'active'
        AND pb.end_at > ?
      WHERE po.user_id = ?
      ORDER BY p.created_at DESC
    `).bind(
      now(),
      user.id
    ).all();

  return json({
    success: true,
    properties:
      result.results || []
  });
}

/* =========================================================
   BOOST PROPERTY
========================================================= */

async function boostProperty(
  request,
  env
) {
  const user =
    await getCurrentUser(
      request,
      env
    );

  if (!user) {
    return json({
      success: false,
      error:
        "Sign in required."
    }, 401);
  }

  const data =
    await request.json();

  const propertyId =
    Number(
      data.property_id
    );

  if (!propertyId) {
    return json({
      success: false,
      error:
        "Property ID is required."
    }, 400);
  }

  const subscription =
    await getActiveSubscription(
      user.id,
      env
    );

  if (!subscription) {
    return json({
      success: false,
      error:
        "An active subscription is required to boost a property."
    }, 403);
  }

  const property =
    await env.DB.prepare(`
      SELECT
        p.id,
        p.title,
        po.user_id
      FROM properties p
      JOIN property_owners po
        ON po.property_id = p.id
      WHERE p.id = ?
        AND po.user_id = ?
    `).bind(
      propertyId,
      user.id
    ).first();

  if (!property) {
    return json({
      success: false,
      error:
        "Property not found or you do not own this property."
    }, 404);
  }

  const existingBoost =
    await env.DB.prepare(`
      SELECT *
      FROM property_boosts
      WHERE property_id = ?
        AND user_id = ?
        AND status = 'active'
        AND end_at > ?
      ORDER BY id DESC
      LIMIT 1
    `).bind(
      propertyId,
      user.id,
      now()
    ).first();

  if (existingBoost) {
    return json({
      success: false,
      error:
        "This property is already boosted.",
      boost:
        existingBoost
    }, 409);
  }

  const unlimited =
    Number(
      subscription.unlimited_boost
    ) === 1;

  if (
    !unlimited &&
    Number(
      user.boost_credits
    ) <= 0
  ) {
    return json({
      success: false,
      error:
        "You have no Boost Credits remaining."
    }, 403);
  }

  const start =
    new Date();

  const end =
    new Date(
      start.getTime() +
      7 *
      24 *
      60 *
      60 *
      1000
    );

  await env.DB.prepare(`
    INSERT INTO property_boosts
    (
      property_id,
      user_id,
      start_at,
      end_at,
      status
    )
    VALUES (?, ?, ?, ?, 'active')
  `).bind(
    propertyId,
    user.id,
    start.toISOString(),
    end.toISOString()
  ).run();

  if (!unlimited) {
    await env.DB.prepare(`
      UPDATE marketplace_users
      SET
        boost_credits =
          boost_credits - 1,
        updated_at = ?
      WHERE id = ?
        AND boost_credits > 0
    `).bind(
      now(),
      user.id
    ).run();

    await env.DB.prepare(`
      UPDATE subscriptions
      SET
        boost_credits_remaining =
          CASE
            WHEN boost_credits_remaining > 0
            THEN boost_credits_remaining - 1
            ELSE 0
          END,
        updated_at = ?
      WHERE id = ?
    `).bind(
      now(),
      subscription.id
    ).run();

    await env.DB.prepare(`
      INSERT INTO boost_transactions
      (
        user_id,
        property_id,
        type,
        credits,
        description
      )
      VALUES (?, ?, 'boost_spend', 1, ?)
    `).bind(
      user.id,
      propertyId,
      "7-day property boost"
    ).run();
  } else {
    await env.DB.prepare(`
      INSERT INTO boost_transactions
      (
        user_id,
        property_id,
        type,
        credits,
        description
      )
      VALUES (?, ?, 'unlimited_boost', 0, ?)
    `).bind(
      user.id,
      propertyId,
      "7-day unlimited property boost"
    ).run();
  }

  return json({
    success: true,
    message:
      "Property boosted successfully for 7 days.",
    property_id:
      propertyId,
    start_at:
      start.toISOString(),
    end_at:
      end.toISOString(),
    unlimited_boost:
      unlimited
  });
}

/* =========================================================
   HEALTH
========================================================= */

async function health(env) {
  let database = false;

  try {
    await env.DB
      .prepare("SELECT 1")
      .first();

    database = true;
  } catch {}

  return json({
    ok: true,
    service:
      "PropertyMarket API",
    database,
    imageStorage:
      !!env.PROPERTY_IMAGES,
    payments:
      !!env.PAYSTACK_SECRET_KEY
  });
}

/* =========================================================
   ROUTER
========================================================= */

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
      new URL(request.url);

    try {
      await ensureDatabase(
        env
      );

      /* =====================================================
         HEALTH
      ===================================================== */

      if (
        url.pathname ===
          "/api/health" ||
        url.pathname ===
          "/health"
      ) {
        return health(env);
      }

      /* =====================================================
         AUTH
      ===================================================== */

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
        const user =
          await getCurrentUser(
            request,
            env
          );

        return json({
          success: true,
          user:
            publicUser(user)
        });
      }

      if (
        url.pathname ===
          "/api/auth/logout" &&
        request.method ===
          "POST"
      ) {
        return logout(
          request,
          env
        );
      }

      /* =====================================================
         PLANS
      ===================================================== */

      if (
        url.pathname ===
          "/api/subscription-plans" &&
        request.method ===
          "GET"
      ) {
        return getPlans(
          env
        );
      }

      /* =====================================================
         SUBSCRIPTION
      ===================================================== */

      if (
        url.pathname ===
          "/api/subscription" &&
        request.method ===
          "GET"
      ) {
        return currentSubscription(
          request,
          env
        );
      }

      /* =====================================================
         PAYMENTS
      ===================================================== */

      if (
        url.pathname ===
          "/api/payments/initialize" &&
        request.method ===
          "POST"
      ) {
        return initializePayment(
          request,
          env
        );
      }

      if (
        url.pathname ===
          "/api/payments/verify" &&
        request.method ===
          "GET"
      ) {
        return verifyPayment(
          request,
          env
        );
      }

      if (
        url.pathname ===
          "/api/payments/webhook" &&
        request.method ===
          "POST"
      ) {
        return paystackWebhook(
          request,
          env
        );
      }

      /* =====================================================
         REFERRALS
      ===================================================== */

      if (
        url.pathname ===
          "/api/referrals" &&
        request.method ===
          "GET"
      ) {
        return referralDashboard(
          request,
          env
        );
      }

      /* =====================================================
         MY PROPERTIES
      ===================================================== */

      if (
        url.pathname ===
          "/api/my-properties" &&
        request.method ===
          "GET"
      ) {
        return myProperties(
          request,
          env
        );
      }

      /* =====================================================
         BOOST
      ===================================================== */

      if (
        url.pathname ===
          "/api/properties/boost" &&
        request.method ===
          "POST"
      ) {
        return boostProperty(
          request,
          env
        );
      }

      /* =====================================================
         PROPERTIES
      ===================================================== */

      if (
        url.pathname ===
          "/api/properties" &&
        request.method ===
          "GET"
      ) {
        return getProperties(
          request,
          env,
          url
        );
      }

      if (
        url.pathname ===
          "/api/properties" &&
        request.method ===
          "POST"
      ) {
        return createProperty(
          request,
          env
        );
      }

      /* =====================================================
         FALLBACK
      ===================================================== */

      return json({
        success: false,
        error:
          "Route not found."
      }, 404);

    } catch (error) {
      console.error(
        "Worker error:",
        error
      );

      return json({
        success: false,
        error:
          error.message ||
          "Internal server error."
      }, 500);
    }
  }
};f
