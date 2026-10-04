export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // =========================
    // DATABASE SETUP
    // =========================
    try {
      await env.DB.batch([
        // Subscription plans
        env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS subscription_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            price INTEGER NOT NULL,
            listing_limit INTEGER NOT NULL,
            boost_credits INTEGER DEFAULT 0,
            unlimited_boosts INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
          )
        `),

        // User subscriptions
        env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            plan_name TEXT NOT NULL,
            amount INTEGER NOT NULL,
            listing_limit INTEGER NOT NULL,
            boost_credits INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending',
            paystack_reference TEXT,
            starts_at TEXT,
            expires_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
          )
        `),

        // Referrals
        env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS referrals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            referrer_user_id INTEGER NOT NULL,
            referred_user_id INTEGER,
            referral_code TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            reward_credits INTEGER DEFAULT 3,
            qualified_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
          )
        `),

        // Boost transactions
        env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS boost_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            property_id INTEGER,
            type TEXT NOT NULL,
            credits INTEGER NOT NULL,
            description TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
          )
        `),

        // Marketplace accounts
        env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS marketplace_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            referral_code TEXT UNIQUE,
            boost_credits INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
          )
        `),

        // Login sessions
        env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS marketplace_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
          )
        `)
      ]);

      // =========================
      // SUBSCRIPTION PLANS
      // =========================

      const plans = [
        ["Starter", 15000, 25, 5, 0],
        ["Professional", 25000, 40, 10, 0],
        ["Business", 35000, 55, 17, 0],
        ["Premium", 50000, 70, 25, 0],
        ["Growth", 70000, 100, 0, 1],
        ["Enterprise", 100000, 150, 0, 1]
      ];

      for (const plan of plans) {
        await env.DB
          .prepare(`
            INSERT OR IGNORE INTO subscription_plans
            (
              name,
              price,
              listing_limit,
              boost_credits,
              unlimited_boosts
            )
            VALUES (?, ?, ?, ?, ?)
          `)
          .bind(...plan)
          .run();
      }

    } catch (error) {
      return Response.json(
        {
          ok: false,
          error: "Database setup failed: " + error.message
        },
        { status: 500 }
      );
    }


    // =========================
    // PASSWORD HASHING
    // =========================

    async function hashPassword(password) {
      const data = new TextEncoder().encode(password);

      const hash = await crypto.subtle.digest(
        "SHA-256",
        data
      );

      return Array.from(new Uint8Array(hash))
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
    }


    // =========================
    // SESSION TOKEN
    // =========================

    function createToken() {
      const bytes = new Uint8Array(32);

      crypto.getRandomValues(bytes);

      return Array.from(bytes)
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
    }


    // =========================
    // GET CURRENT USER
    // =========================

    async function getCurrentUser() {
      const authHeader =
        request.headers.get("Authorization");

      if (!authHeader) {
        return null;
      }

      const token =
        authHeader.replace("Bearer ", "").trim();

      if (!token) {
        return null;
      }

      const result = await env.DB
        .prepare(`
          SELECT
            marketplace_users.id,
            marketplace_users.full_name,
            marketplace_users.email,
            marketplace_users.phone,
            marketplace_users.role,
            marketplace_users.status,
            marketplace_users.referral_code,
            marketplace_users.boost_credits
          FROM marketplace_sessions
          JOIN marketplace_users
            ON marketplace_users.id = marketplace_sessions.user_id
          WHERE marketplace_sessions.token = ?
            AND marketplace_sessions.expires_at > datetime('now')
        `)
        .bind(token)
        .first();

      return result || null;
    }


    // =========================
    // HEALTH CHECK
    // =========================

    if (url.pathname === "/api/health") {
      return Response.json({
        ok: true,
        service: "PropertyMarket API",
        database: !!env.DB,
        imageStorage: !!env.PROPERTY_IMAGES
      });
    }


    // =========================
    // REGISTER ACCOUNT
    // =========================

    if (
      request.method === "POST" &&
      url.pathname === "/api/auth/register"
    ) {
      try {
        const body = await request.json();

        const fullName =
          String(body.full_name || "").trim();

        const email =
          String(body.email || "")
            .trim()
            .toLowerCase();

        const phone =
          String(body.phone || "").trim();

        const password =
          String(body.password || "");

        const role =
          String(body.role || "").trim().toLowerCase();

        const allowedRoles = [
          "agent",
          "landlord",
          "developer"
        ];

        if (
          !fullName ||
          !email ||
          !password ||
          !role
        ) {
          return Response.json(
            {
              ok: false,
              error:
                "Full name, email, password and account type are required."
            },
            { status: 400 }
          );
        }

        if (!allowedRoles.includes(role)) {
          return Response.json(
            {
              ok: false,
              error:
                "Account type must be agent, landlord or developer."
            },
            { status: 400 }
          );
        }

        if (password.length < 8) {
          return Response.json(
            {
              ok: false,
              error:
                "Password must be at least 8 characters."
            },
            { status: 400 }
          );
        }

        const existing =
          await env.DB
            .prepare(`
              SELECT id
              FROM marketplace_users
              WHERE email = ?
            `)
            .bind(email)
            .first();

        if (existing) {
          return Response.json(
            {
              ok: false,
              error:
                "An account with this email already exists."
            },
            { status: 409 }
          );
        }

        const passwordHash =
          await hashPassword(password);

        const result =
          await env.DB
            .prepare(`
              INSERT INTO marketplace_users (
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

        return Response.json(
          {
            ok: true,
            message:
              "Account created successfully.",
            userId:
              result.meta?.last_row_id || null,
            role
          },
          { status: 201 }
        );

      } catch (error) {
        return Response.json(
          {
            ok: false,
            error: error.message
          },
          { status: 500 }
        );
      }
    }


    // =========================
    // LOGIN
    // =========================

    if (
      request.method === "POST" &&
      url.pathname === "/api/auth/login"
    ) {
      try {
        const body = await request.json();

        const email =
          String(body.email || "")
            .trim()
            .toLowerCase();

        const password =
          String(body.password || "");

        if (!email || !password) {
          return Response.json(
            {
              ok: false,
              error:
                "Email and password are required."
            },
            { status: 400 }
          );
        }

        const user =
          await env.DB
            .prepare(`
              SELECT *
              FROM marketplace_users
              WHERE email = ?
            `)
            .bind(email)
            .first();

        if (!user) {
          return Response.json(
            {
              ok: false,
              error:
                "Invalid email or password."
            },
            { status: 401 }
          );
        }

        const passwordHash =
          await hashPassword(password);

        if (passwordHash !== user.password_hash) {
          return Response.json(
            {
              ok: false,
              error:
                "Invalid email or password."
            },
            { status: 401 }
          );
        }

        if (user.status !== "active") {
          return Response.json(
            {
              ok: false,
              error:
                "This account is not active."
            },
            { status: 403 }
          );
        }

        const token = createToken();

        const expiresAt =
          new Date(
            Date.now() +
            1000 * 60 * 60 * 24 * 30
          ).toISOString();

        await env.DB
          .prepare(`
            INSERT INTO marketplace_sessions (
              user_id,
              token,
              expires_at
            )
            VALUES (?, ?, ?)
          `)
          .bind(
            user.id,
            token,
            expiresAt
          )
          .run();

        return Response.json({
          ok: true,
          message: "Login successful.",
          token,
          user: {
            id: user.id,
            full_name: user.full_name,
            email: user.email,
            phone: user.phone,
            role: user.role,
            referral_code: user.referral_code,
            boost_credits: user.boost_credits
          }
        });

      } catch (error) {
        return Response.json(
          {
            ok: false,
            error: error.message
          },
          { status: 500 }
        );
      }
    }


    // =========================
    // CURRENT USER
    // =========================

    if (
      request.method === "GET" &&
      url.pathname === "/api/auth/me"
    ) {
      try {
        const user =
          await getCurrentUser();

        if (!user) {
          return Response.json(
            {
              ok: false,
              error: "Not authenticated."
            },
            { status: 401 }
          );
        }

        return Response.json({
          ok: true,
          user
        });

      } catch (error) {
        return Response.json(
          {
            ok: false,
            error: error.message
          },
          { status: 500 }
        );
      }
    }


    // =========================
    // LOGOUT
    // =========================

    if (
      request.method === "POST" &&
      url.pathname === "/api/auth/logout"
    ) {
      try {
        const authHeader =
          request.headers.get("Authorization");

        if (authHeader) {
          const token =
            authHeader
              .replace("Bearer ", "")
              .trim();

          if (token) {
            await env.DB
              .prepare(`
                DELETE FROM marketplace_sessions
                WHERE token = ?
              `)
              .bind(token)
              .run();
          }
        }

        return Response.json({
          ok: true,
          message: "Logged out successfully."
        });

      } catch (error) {
        return Response.json(
          {
            ok: false,
            error: error.message
          },
          { status: 500 }
        );
      }
    }


    // =========================
    // GET SUBSCRIPTION PLANS
    // =========================

    if (
      request.method === "GET" &&
      url.pathname === "/api/subscription-plans"
    ) {
      try {
        const result =
          await env.DB
            .prepare(`
              SELECT
                id,
                name,
                price,
                listing_limit,
                boost_credits,
                unlimited_boosts
              FROM subscription_plans
              ORDER BY price ASC
            `)
            .all();

        return Response.json({
          ok: true,
          plans: result.results || []
        });

      } catch (error) {
        return Response.json(
          {
            ok: false,
            error: error.message
          },
          { status: 500 }
        );
      }
    }


    // =========================
    // GET ALL PROPERTIES
    // =========================

    if (
      request.method === "GET" &&
      url.pathname === "/api/properties"
    ) {
      try {
        const result =
          await env.DB
            .prepare(`
              SELECT *
              FROM properties
              ORDER BY created_at DESC
            `)
            .all();

        return Response.json({
          ok: true,
          properties:
            result.results || []
        });

      } catch (error) {
        return Response.json(
          {
            ok: false,
            error: error.message
          },
          { status: 500 }
        );
      }
    }


    // =========================
    // CREATE PROPERTY LISTING
    // =========================

    if (
      request.method === "POST" &&
      url.pathname === "/api/properties"
    ) {
      try {
        const body =
          await request.json();

        const title =
          String(body.title || "").trim();

        const description =
          String(body.description || "").trim();

        const category =
          String(body.category || "").trim();

        const propertyType =
          String(body.property_type || "").trim();

        const price =
          Number(body.price || 0);

        const location =
          String(body.location || "").trim();

        const bedrooms =
          Number(body.bedrooms || 0);

        const bathrooms =
          Number(body.bathrooms || 0);

        const area =
          String(body.area || "").trim();

        const amenities =
          String(body.amenities || "").trim();

        if (
          !title ||
          !description ||
          !propertyType ||
          !location ||
          !price
        ) {
          return Response.json(
            {
              ok: false,
              error:
                "Title, description, property type, price and location are required."
            },
            { status: 400 }
          );
        }

        const result =
          await env.DB
            .prepare(`
              INSERT INTO properties (
                title,
                description,
                category,
                property_type,
                price,
                location,
                bedrooms,
                bathrooms,
                area,
                amenities
              )
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `)
            .bind(
              title,
              description,
              category,
              propertyType,
              price,
              location,
              bedrooms,
              bathrooms,
              area,
              amenities
            )
            .run();

        return Response.json(
          {
            ok: true,
            message:
              "Property listing created successfully.",
            propertyId:
              result.meta?.last_row_id || null
          },
          { status: 201 }
        );

      } catch (error) {
        return Response.json(
          {
            ok: false,
            error: error.message
          },
          { status: 500 }
        );
      }
    }


    // =========================
    // SERVE WEBSITE
    // =========================

    return env.ASSETS.fetch(request);
  }
};
