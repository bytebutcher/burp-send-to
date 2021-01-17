package net.bytebutcher.burpsendtoextension.parser;

import com.google.gson.*;
import net.bytebutcher.burpsendtoextension.models.placeholder.behaviour.CommandSeparatedPlaceholderBehaviour;
import net.bytebutcher.burpsendtoextension.models.placeholder.behaviour.PlaceholderBehaviour;
import net.bytebutcher.burpsendtoextension.models.placeholder.behaviour.StringSeparatedPlaceholderBehaviour;

import java.lang.reflect.Type;

public class CommandObjectFileParser {

    private static Gson parser = null;

    private CommandObjectFileParser() {}

    private static class PlaceholderBehaviourDeserializer implements JsonDeserializer<PlaceholderBehaviour> {
        @Override
        public PlaceholderBehaviour deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
            JsonObject rootObject = json.getAsJsonObject();
            if (rootObject.has("placeholder") && rootObject.has("separator")) {
                return new StringSeparatedPlaceholderBehaviour(
                        rootObject.get("placeholder").getAsString(),
                        rootObject.get("separator").getAsString());
            } else if (rootObject.has("placeholder")) {
                return new CommandSeparatedPlaceholderBehaviour(
                        rootObject.get("placeholder").getAsString());
            } else {
                return null;
            }
        }
    }

    public static Gson getParser() {
        if (parser == null) {
            // Note: Usually we would use the TypeAdapterFactory here:
            //
            //       parser = new GsonBuilder().registerTypeAdapterFactory(
            //           RuntimeTypeAdapterFactory.of(PlaceholderBehaviour.class, "type")
            //           .registerSubtype(StringSeparatedPlaceholderBehaviour.class, "StringSeparated")
            //           .registerSubtype(CommandSeparatedPlaceholderBehaviour.class, "CommandSeparated")
            //       ).create();
            //
            //       This would add a type field to the PlaceholderBehavior JSON representation.
            //
            //       However, since the TypeAdapterFactory was not used from the beginning there is the
            //       chance that a user loads a PlaceholderBehavior in which the type field is not present.
            //       For those cases we would need to use the PlaceholderBehaviourDeserializer, anyway.
            //
            parser = new GsonBuilder()
                    .registerTypeHierarchyAdapter(PlaceholderBehaviour.class, new PlaceholderBehaviourDeserializer())
                    .create();
        }
        return parser;
    }

}
