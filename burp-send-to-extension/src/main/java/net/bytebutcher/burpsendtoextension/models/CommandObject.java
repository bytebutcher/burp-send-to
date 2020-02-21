package net.bytebutcher.burpsendtoextension.models;

import com.google.common.collect.Lists;
import com.google.gson.annotations.SerializedName;
import net.bytebutcher.burpsendtoextension.models.placeholder.AbstractRequestResponseInfoPlaceholder;
import net.bytebutcher.burpsendtoextension.models.placeholder.AbstractRequestResponsePlaceholder;
import net.bytebutcher.burpsendtoextension.models.placeholder.IPlaceholderParser;
import net.bytebutcher.burpsendtoextension.models.placeholder.behaviour.CommandSeparatedPlaceholderBehaviour;
import net.bytebutcher.burpsendtoextension.models.placeholder.behaviour.PlaceholderBehaviour;
import net.bytebutcher.burpsendtoextension.models.placeholder.behaviour.StringSeparatedPlaceholderBehaviour;
import net.bytebutcher.burpsendtoextension.utils.StringUtils;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

public class CommandObject {

    private String id = UUID.randomUUID().toString();
    private String name;
    @SerializedName(value="format", alternate={"command"}) // Changed field name from "command" to "format" in version 1.1
    private String format;
    private String group;
    private ERuntimeBehaviour runtimeBehaviour;
    private boolean showPreview;
    private List<PlaceholderBehaviour> placeholderBehaviourList;

    public CommandObject(String name, String format, String group, ERuntimeBehaviour runtimeBehaviour, boolean showPreview, List<PlaceholderBehaviour> placeholderBehaviourList) {
        this.name = name;
        this.format = format;
        this.group = group;
        this.runtimeBehaviour = runtimeBehaviour;
        this.showPreview = showPreview;
        this.placeholderBehaviourList = initPlaceholderBehaviourList(placeholderBehaviourList);
    }

    public CommandObject(String id, String name, String format, String group, ERuntimeBehaviour runtimeBehaviour, boolean showPreview, List<PlaceholderBehaviour> placeholderBehaviourList) {
        this(name, format, group, runtimeBehaviour, showPreview, placeholderBehaviourList);
        this.id = id;
    }

    /**
     * Returns the behaviour of each placeholder.
     * @param placeholderBehaviourList a (incomplete) placeholder behaviour list which is used as base. if this list is
     *                                 empty (e.g. when no placeholder behaviour was defined by the user), each
     *                                 placeholder found in the command is associated with a default placeholder behaviour.
     *                                 Otherwise the placeholder behaviour in the given list is used.
     * @return the behaviour of each placeholder.
     */
    private List<PlaceholderBehaviour> initPlaceholderBehaviourList(List<PlaceholderBehaviour> placeholderBehaviourList) {
        List<PlaceholderBehaviour> result = Lists.newArrayList();
        List<PlaceholderBehaviour> originalPlaceholderBehaviour = Lists.newArrayList(placeholderBehaviourList);
        List<String> placeholders = Placeholders.get(getFormat());
        for (String placeholder : placeholders) {
            if (getPlaceholders(originalPlaceholderBehaviour).contains(placeholder)) {
                for (int i = 0; i < originalPlaceholderBehaviour.size(); i++) {
                    if (placeholder.equals(originalPlaceholderBehaviour.get(i).getPlaceholder())) {
                        result.add(originalPlaceholderBehaviour.get(i));
                        originalPlaceholderBehaviour.remove(i);
                        break;
                    }
                }
            } else {
                result.add(new CommandSeparatedPlaceholderBehaviour(placeholder)); // Default separator
            }
        }
        return result;
    }

    public String getId() { return this.id; }

    public String getName() {
        return this.name;
    }

    public String getFormat() {
        return this.format;
    }

    public String getGroup() {
        return group;
    }

    public ERuntimeBehaviour getRuntimeBehaviour() {
        return this.runtimeBehaviour != null ? this.runtimeBehaviour : ERuntimeBehaviour.RUN_IN_TERMINAL;
    }

    public boolean shouldRunInTerminal() {
        return getRuntimeBehaviour() == ERuntimeBehaviour.RUN_IN_TERMINAL;
    }

    public boolean shouldOutputReplaceSelection() {
        return getRuntimeBehaviour() == ERuntimeBehaviour.OUTPUT_SHOULD_REPLACE_SELECTION;
    }

    public boolean shouldRunInBackground() {
        return getRuntimeBehaviour() == ERuntimeBehaviour.RUN_IN_BACKGROUND;
    }

    public void setShowPreview(boolean showPreview) {
        this.showPreview = showPreview;
    }

    public boolean shouldShowPreview() {
        return this.showPreview;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CommandObject that = (CommandObject) o;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    public List<Map<String, IPlaceholderParser>> getValid(List<Map<String, IPlaceholderParser>> placeholders, Context context) {
        List<Map<String, IPlaceholderParser>> validItems = Lists.newArrayList();
        for (Map<String, IPlaceholderParser> placeholderMap : placeholders) {
            if (isValid(placeholderMap, context)) {
                validItems.add(placeholderMap);
            }
        }
        return validItems;
    }

    private boolean isValid(Map<String, IPlaceholderParser> placeholderMap, Context context) {
        for (String placeholder : getPlaceholders(getPlaceholderBehaviourList())) {
            if (placeholderMap.containsKey(placeholder)) {
                if (!placeholderMap.get(placeholder).isValid(context)) {
                    return false;
                }
            }
        }
        return true;
    }

    public boolean doesRequireRequestResponse(Map<String, IPlaceholderParser> placeholderMap) {
        for (String placeholder : getPlaceholders(getPlaceholderBehaviourList())) {
            if (placeholderMap.containsKey(placeholder)) {
                if (placeholderMap.get(placeholder) instanceof AbstractRequestResponseInfoPlaceholder || placeholderMap.get(placeholder) instanceof AbstractRequestResponsePlaceholder) {
                    return true;
                }
            }
        }
        return false;
    }

    private List<String> getPlaceholders(List<PlaceholderBehaviour> placeholderBehaviourList) {
        return placeholderBehaviourList.stream().map(PlaceholderBehaviour::getPlaceholder).collect(Collectors.toList());
    }

    /**
     * Returns the command while all placeholders are replaced with their associated value as String.
     * @throws Exception when retrieving/replacing a placeholder failed.
     */
    public String getCommand(List<Map<String, IPlaceholderParser>> placeholderMap, Context context) throws Exception {
        try {
            List<String> result = Lists.newArrayList();
            boolean containsCommandSeparatedPlaceholderBehaviour = getPlaceholderBehaviourList().stream().anyMatch(c -> c instanceof CommandSeparatedPlaceholderBehaviour);
            if (containsCommandSeparatedPlaceholderBehaviour) {
                for (int messageIndex = 0; messageIndex < placeholderMap.size(); messageIndex++) {
                    String command = getFormat();
                    int placeholderIndex = 0;
                    for (String internalPlaceHolder : getPlaceholders(getPlaceholderBehaviourList())) {
                        command = replaceCommandPlaceholder(internalPlaceHolder, placeholderMap, messageIndex, placeholderIndex, command, context);
                        placeholderIndex++;
                    }
                    result.add(command);
                }
            } else {
                String command = getFormat();
                int messageIndex = 0;
                int placeholderIndex = 0;
                for (String internalPlaceHolder : getPlaceholders(getPlaceholderBehaviourList())) {
                    command = replaceCommandPlaceholder(internalPlaceHolder, placeholderMap, messageIndex, placeholderIndex, command, context);
                    placeholderIndex++;
                }
                result.add(command);
            }
            return result.stream().collect(Collectors.joining("\n"));
        } catch (RuntimeException e) {
            // Rethrow from unchecked to checked exception. We only deal with RuntimeException here, since streams
            // (here: placeholderMap.stream()) does not handle checked exceptions well.
            throw new Exception(e);
        }
    }

    private String replaceCommandPlaceholder(String internalPlaceHolder, List<Map<String, IPlaceholderParser>> placeholderMap, int messageIndex, int placeholderIndex, String command, Context context) {
        boolean isCommandSeparated = getPlaceholderBehaviourList().get(placeholderIndex) instanceof CommandSeparatedPlaceholderBehaviour;
        String value = null;
        if (isCommandSeparated) {
            // use the value from the actual message
            value = placeholderMap.get(messageIndex).get(internalPlaceHolder).getValue(context);
        } else {
            // combine the values of all messages using the defined placeholder separator
            value = getValid(placeholderMap, context).stream().map(m -> m.get(internalPlaceHolder)).map(iPlaceholder -> iPlaceholder.getValue(context)).collect(Collectors.joining(((StringSeparatedPlaceholderBehaviour) getPlaceholderBehaviourList().get(messageIndex)).getSeparator()));
        }
        boolean doesRequireShellEscape = placeholderMap.get(0).get(internalPlaceHolder).doesRequireShellEscape();
        command = command.replace(internalPlaceHolder, doesRequireShellEscape ? "'" + StringUtils.shellEscape(value) + "'" : value);
        return command;
    }

    public List<PlaceholderBehaviour> getPlaceholderBehaviourList() {
        if (placeholderBehaviourList == null) {
            // placeholder behaviour list might be null, when CommandObject was loaded from config and no placeholder
            // behaviour was defined.
            placeholderBehaviourList = initPlaceholderBehaviourList(Lists.newArrayList());
        }
        return Lists.newArrayList(placeholderBehaviourList);
    }
}
