export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // =========================
    // DATABASE SETUP
    // =========================
    try {
      await env.DB.batch([
        env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS subscription_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            price INTEGER NOT NULL,
            listing_limit INTEGER NOT NULL,
            boost_credits INTEGER,
            unlimited_boosts INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
          )
        `),

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
        `)
      ]);

      // =========================
      // INSERT SUBSCRIPTION PLANS
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
            (name, price, listing_limit, boost_credits, unlimited_boosts)
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
    // API HEALTH CHECK
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
    // GET ALL PROPERTIES
    // =========================
    if (
      request.method === "GET" &&
      url.pathname === "/api/properties"
    ) {
      try {
        const result = await env.DB
          .prepare(`
            SELECT *
            FROM properties
            ORDER BY created_at DESC
          `)
          .all();

        return Response.json({
          ok: true,
          properties: result.results || []
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

        const body = await request.json();

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


        // Required fields
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


        const result = await env.DB
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
