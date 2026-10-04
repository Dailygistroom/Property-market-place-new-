export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // API test route
    if (url.pathname.startsWith("/api/")) {
      return Response.json({
        ok: true,
        message: "PropertyMarket API is online"
      });
    }

    // Serve the website
    return env.ASSETS.fetch(request);
  }
};
