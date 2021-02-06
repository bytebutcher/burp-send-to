package net.bytebutcher.burpsendtoextension.builder;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import net.bytebutcher.burpsendtoextension.models.CommandObject;
import net.bytebutcher.burpsendtoextension.models.Context;
import net.bytebutcher.burpsendtoextension.models.placeholder.IPlaceholderParser;
import net.bytebutcher.burpsendtoextension.models.placeholder.behaviour.CommandSeparatedPlaceholderBehaviour;
import net.bytebutcher.burpsendtoextension.models.placeholder.behaviour.FileSeparatedPlaceholderBehaviour;
import net.bytebutcher.burpsendtoextension.models.placeholder.behaviour.IPlaceholderBehaviour;
import net.bytebutcher.burpsendtoextension.models.placeholder.behaviour.StringSeparatedPlaceholderBehaviour;

import java.io.File;
import java.io.PrintWriter;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class CommandBuilder {

    // The model of the context menu entry with the format string and various options.
    private final CommandObject commandObject;

    // List of selected messages containing the placeholders and their values.
    private final List<Map<String, IPlaceholderParser>> placeholderMap;

    // List of placeholders and merged values.
    private final Map<Placeholder, String> placeholderValues;

    private final Context context;

    private static class Placeholder {

        private final String name;
        private final IPlaceholderBehaviour behaviour;

        public Placeholder(CommandObject.Placeholder placeholder) {
            this.name = placeholder.getName();
            this.behaviour = placeholder.getBehaviour();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Placeholder that = (Placeholder) o;
            return Objects.equals(name, that.name) && Objects.equals(behaviour, that.behaviour);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name, behaviour);
        }
    }

    public CommandBuilder(CommandObject commandObject, List<Map<String, IPlaceholderParser>> placeholderMap, Context context) throws Exception {
        this.commandObject = commandObject;
        this.placeholderMap = placeholderMap;
        this.context = context;
        this.placeholderValues = initPlaceholderValues();
    }

    public Map<Placeholder, String> initPlaceholderValues() throws Exception {
        Map<Placeholder, String> placeholderValues = Maps.newHashMap();
        for (CommandObject.Placeholder coPlaceholder : commandObject.getPlaceholders()) {
            Placeholder cbPlaceholder = new Placeholder(coPlaceholder);
            if (!placeholderValues.containsKey(cbPlaceholder)) {
                if (coPlaceholder.getBehaviour() instanceof StringSeparatedPlaceholderBehaviour){
                    // combine the values of all messages using the defined placeholder separator
                    placeholderValues.put(cbPlaceholder, commandObject.getValid(placeholderMap, context).stream()
                            .map(m -> m.get(coPlaceholder.getName()))
                            .map(iPlaceholder -> iPlaceholder.getValue(context))
                            .collect(Collectors.joining(((StringSeparatedPlaceholderBehaviour) coPlaceholder.getBehaviour()).getSeparator())));
                } else if (coPlaceholder.getBehaviour() instanceof FileSeparatedPlaceholderBehaviour){
                    // combine the values of all messages and write them into a file.
                    placeholderValues.put(cbPlaceholder, writeToFile(commandObject.getValid(placeholderMap, context).stream()
                            .map(m -> m.get(coPlaceholder.getName()))
                            .map(iPlaceholder -> iPlaceholder.getValue(context))
                            .collect(Collectors.joining("\n"))));
                }
            }
        }
        return placeholderValues;
    }

    /**
     * Returns the command while all placeholders are replaced with their associated value as String.
     * @throws Exception when retrieving/replacing a placeholder failed.
     */
    public String build() throws Exception {
        try {
            List<String> result = Lists.newArrayList();
            boolean containsCommandSeparatedPlaceholderBehaviour = commandObject.getPlaceholders().stream()
                    .map(CommandObject.Placeholder::getBehaviour)
                    .anyMatch(c -> c instanceof CommandSeparatedPlaceholderBehaviour);
            if (containsCommandSeparatedPlaceholderBehaviour) {
                for (int messageIndex = 0; messageIndex < placeholderMap.size(); messageIndex++) {
                    result.add(buildByMessage(messageIndex));
                }
            } else {
                result.add(buildByMessage(0));
            }
            return String.join("\n", result);
        } catch (RuntimeException e) {
            // Rethrow from unchecked to checked exception. We only deal with RuntimeException here, since streams
            // (here: placeholderMap.stream()) does not handle checked exceptions well.
            throw new Exception(e);
        }
    }

    private String buildByMessage(int messageIndex) throws Exception {
        StringBuffer format = new StringBuffer(commandObject.getFormat());
        // For each placeholder, starting from the placeholder at the very end, replace it with the value from the message.
        List<CommandObject.Placeholder> placeholders = commandObject.getPlaceholders().stream().sorted(
                Comparator.comparing(CommandObject.Placeholder::getEnd).reversed()
        ).collect(Collectors.toList());
        for (CommandObject.Placeholder placeholder : placeholders) {
            replaceCommandPlaceholder(placeholder, placeholderMap, messageIndex, format, context);
        }
        return format.toString();
    }

    private void replaceCommandPlaceholder(CommandObject.Placeholder placeholder, List<Map<String, IPlaceholderParser>> placeholderMap, int messageIndex, StringBuffer command, Context context) throws Exception {
        String value;
        if (placeholderValues.containsKey(new Placeholder(placeholder))) {
            // merged values
            value = placeholderValues.get(new Placeholder(placeholder));
        } else {
            // command separated - use the value from the actual message
            value = placeholderMap.get(messageIndex).get(placeholder.getName()).getValue(context);
        }
        command.replace(placeholder.getStart(), placeholder.getEnd(), value);
    }

    private String writeToFile(String value) throws Exception {
        try {
            File tmp = File.createTempFile("burp_", ".snd");
            PrintWriter out = new PrintWriter(tmp.getPath());
            out.write(value);
            out.flush();
            return tmp.getAbsolutePath();
        } catch (RuntimeException e) {
            throw new Exception(this.getClass().getSimpleName() + ": Error writing to temporary file!", e);
        }
    }
}