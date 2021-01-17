package net.bytebutcher.burpsendtoextension.parser;

import com.google.gson.*;
import net.bytebutcher.burpsendtoextension.models.placeholder.behaviour.CommandSeparatedPlaceholderBehaviour;
import net.bytebutcher.burpsendtoextension.models.placeholder.behaviour.PlaceholderBehaviour;
import net.bytebutcher.burpsendtoextension.models.placeholder.behaviour.StringSeparatedPlaceholderBehaviour;

import java.lang.reflect.Type;

public class PlaceholderBehaviourDeserializer implements JsonDeserializer<PlaceholderBehaviour> {
    @Override
    public PlaceholderBehaviour deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        JsonObject rootObject = json.getAsJsonObject();
        if (rootObject.has("placeholder") && rootObject.has("separator")) {
            return new StringSeparatedPlaceholderBehaviour(
                    String.valueOf(rootObject.get("placeholder")), String.valueOf(rootObject.get("separator")));
        } else if (rootObject.has("placeholder")) {
            return new CommandSeparatedPlaceholderBehaviour(
                    String.valueOf(rootObject.get("placeholder")));
        } else {
            return null;
        }
    }
}
