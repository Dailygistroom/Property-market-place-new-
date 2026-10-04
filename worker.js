export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Backend health check
    if (url.pathname === "/api/health") {
      return Response.json({
        ok: true,
        service: "PropertyMarket API",
        database: !!env.DB,
        imageStorage: !!env.PROPERTY_IMAGES
      });
    }

    // Serve the existing PropertyMarket website
    return env.ASSETS.fetch(request);
  }
};
