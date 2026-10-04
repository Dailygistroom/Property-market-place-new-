export default {
  async fetch(request, env) {
    const url = new URL(request.url);

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
