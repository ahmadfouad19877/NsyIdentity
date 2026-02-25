namespace IdentityServerNSY.Security.Sherd;

using System.Collections.Concurrent;

public static class AppSecrets
{
    private static readonly ConcurrentDictionary<string, string> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    private static bool _loaded;

    /// <summary>
    /// Reads values from APP_SECRETS_FILE (docker secret) as KEY=VALUE lines.
    /// Supports SERVICE_KEY prefix (e.g. CURRENCY_DB_CONNECTION).
    /// Falls back to environment variables for local dev.
    /// </summary>
    public static string Get(string key)
    {
        EnsureLoaded();

        // 1) Prefixed key: {SERVICE_KEY}_{key}
        var serviceKey = Environment.GetEnvironmentVariable("SERVICE_KEY");
        if (!string.IsNullOrWhiteSpace(serviceKey))
        {
            var prefixedKey = $"{serviceKey}_{key}";

            if (_cache.TryGetValue(prefixedKey, out var pv) && !string.IsNullOrWhiteSpace(pv))
                return pv;

            var penv = Environment.GetEnvironmentVariable(prefixedKey);
            if (!string.IsNullOrWhiteSpace(penv))
                return penv;
        }

        // 2) Global key
        if (_cache.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v))
            return v;

        var env = Environment.GetEnvironmentVariable(key);
        if (!string.IsNullOrWhiteSpace(env))
            return env;

        throw new Exception($"Missing required key: {key} (SERVICE_KEY={serviceKey ?? "none"})");
    }

    public static string? TryGet(string key)
    {
        try { return Get(key); }
        catch { return null; }
    }

    private static void EnsureLoaded()
    {
        if (_loaded) return;

        var path = Environment.GetEnvironmentVariable("APP_SECRETS_FILE");
        if (string.IsNullOrWhiteSpace(path))
        {
            _loaded = true; // local dev -> env/appsettings
            return;
        }

        if (!File.Exists(path))
            throw new Exception($"APP_SECRETS_FILE not found: {path}");

        foreach (var raw in File.ReadAllLines(path))
        {
            var line = raw.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                continue;

            var idx = line.IndexOf('=');
            if (idx <= 0) continue;

            var k = line[..idx].Trim();
            var val = line[(idx + 1)..].Trim();

            if (!string.IsNullOrWhiteSpace(k))
                _cache[k] = val;
        }

        _loaded = true;
    }
}
