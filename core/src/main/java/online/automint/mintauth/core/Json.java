// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;

public final class Json {
    public static final Gson GSON =
            new GsonBuilder().disableHtmlEscaping().serializeNulls().create();

    private Json() {}

    public static JsonObject object(String text, int maxBytes) {
        if (text == null || text.getBytes(StandardCharsets.UTF_8).length > maxBytes)
            throw new IllegalArgumentException("JSON_LIMIT");
        JsonReader reader = new JsonReader(new StringReader(text));
        reader.setStrictness(Strictness.STRICT);
        JsonElement value = JsonParser.parseReader(reader);
        try {
            if (reader.peek() != JsonToken.END_DOCUMENT)
                throw new IllegalArgumentException("JSON_TRAILING_CONTENT");
        } catch (java.io.IOException invalid) {
            throw new IllegalArgumentException("JSON_INVALID");
        }
        if (!value.isJsonObject()) throw new IllegalArgumentException("JSON_OBJECT_REQUIRED");
        return value.getAsJsonObject();
    }

    public static String string(JsonObject obj, String key) {
        JsonElement value = obj.get(key);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString())
            throw new IllegalArgumentException("MISSING_FIELD");
        return value.getAsString();
    }

    public static String optional(JsonObject obj, String key) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? string(obj, key) : null;
    }

    public static JsonObject obj(String key, String value) {
        JsonObject obj = new JsonObject();
        obj.addProperty(key, value);
        return obj;
    }

    public static JsonObject copy(JsonObject object) {
        return object.deepCopy();
    }
}
