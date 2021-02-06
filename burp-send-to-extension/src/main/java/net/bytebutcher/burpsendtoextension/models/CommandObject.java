package net.bytebutcher.burpsendtoextension.models;

import burp.BurpExtender;
import com.google.common.collect.Lists;
import com.google.gson.annotations.SerializedName;
import net.bytebutcher.burpsendtoextension.models.placeholder.AbstractRequestResponseInfoPlaceholder;
import net.bytebutcher.burpsendtoextension.models.placeholder.AbstractRequestResponsePlaceholder;
import net.bytebutcher.burpsendtoextension.models.placeholder.IPlaceholderParser;
import net.bytebutcher.burpsendtoextension.models.placeholder.behaviour.CommandSeparatedPlaceholderBehaviour;
import net.bytebutcher.burpsendtoextension.models.placeholder.behaviour.IPlaceholderBehaviour;

import java.util.*;

public class CommandObject {

    private String id = UUID.randomUUID().toString();
    private String name;
    @SerializedName(value="format", alternate={"command"}) // Changed field name from "command" to "format" in version 1.1
    private String format;
    private String group;
    private ERuntimeBehaviour runtimeBehaviour;
    private boolean showPreview;
    private List<CommandObject.Placeholder> placeholders;

    public static class Placeholder {

        // The name of the placeholder (e.g. "%U").
        private final String name;

        // Defines at which position the placeholder is found in the format string.
        private final int start;
        private final int end;

        // The behavior of the placeholder.
        private IPlaceholderBehaviour behaviour;

        public Placeholder(String placeholder, IPlaceholderBehaviour behaviour, int start, int end) {
            this.name = placeholder;
            this.behaviour = behaviour;
            this.start = start;
            this.end = end;
        }

        public String getName() {
            return name;
        }

        public int getStart() {
            return start;
        }

        public int getEnd() {
            return end;
        }

        @Override
        public String toString() {
            return "Placeholder{" +
                    "name='" + name + '\'' +
                    ", start=" + start +
                    ", end=" + end +
                    ", behaviour=" + behaviour +
                    '}';
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Placeholder that = (Placeholder) o;
            return Objects.equals(name, that.name);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name);
        }

        public IPlaceholderBehaviour getBehaviour() {
            return behaviour;
        }

        public void setBehaviour(IPlaceholderBehaviour behaviour) {
            this.behaviour = behaviour;
        }

    }

    public CommandObject(String name, String format, String group, ERuntimeBehaviour runtimeBehaviour, boolean showPreview, List<Placeholder> placeholders) {
        this.name = name;
        this.format = format;
        this.group = group;
        this.runtimeBehaviour = runtimeBehaviour;
        this.showPreview = showPreview;
        this.placeholders = initPlaceholders(Lists.newArrayList(placeholders));
    }

    public CommandObject(String id, String name, String format, String group, ERuntimeBehaviour runtimeBehaviour, boolean showPreview, List<Placeholder> placeholders) {
        this(name, format, group, runtimeBehaviour, showPreview, placeholders);
        this.id = id;
    }

    public CommandObject(String name, String format, String group, ERuntimeBehaviour runtimeBehaviour, boolean showPreview) {
        this(name, format, group, runtimeBehaviour, showPreview, Lists.newArrayList());
    }

    /**
     * Each context menu entry has a string format. The string format may contain placeholders.
     * The user can specify the behaviour of the placeholder which is stored in configuration.
     * This method links the placeholders and it's behavior.
     *
     * This method addresses the problem that the string format might have been changed (e.g. added/removed placeholder)
     * while the behavior was not. As a result this method need to autodetect whether the stored behavior can still be
     * applied or whether a default behaviour needs to be set.
     *
     * @param storedPlaceholders a (incomplete) list of placeholders. if this list is
     *                                 empty (e.g. when no placeholder was defined by the user), each
     *                                 placeholder found in the command is associated with a default placeholder behaviour.
     *                                 Otherwise the placeholder behaviour in the given list is used.
     * @return the behaviour of each placeholder.
     */
    private List<CommandObject.Placeholder> initPlaceholders(List<CommandObject.Placeholder> storedPlaceholders) {
        // Get the placeholders defined in the format string
        List<CommandObject.Placeholder> actualPlaceholders = Placeholders.get(this.format);
        for (CommandObject.Placeholder actualPlaceholder : actualPlaceholders) {
            // Check whether a placeholder behavior exists for this placeholder.
            // We pick the first one we find which might not always be correct - but we can't do it any other way.
            Placeholder match = storedPlaceholders.stream().filter(x -> x.getName().equals(actualPlaceholder.getName())).findFirst().orElse(null);
            if (match != null && match.getBehaviour() != null) {
                actualPlaceholder.setBehaviour(match.getBehaviour());
            } else {
                actualPlaceholder.setBehaviour(new CommandSeparatedPlaceholderBehaviour());
            }
            storedPlaceholders.remove(match);
        }
        return actualPlaceholders;
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
        for (CommandObject.Placeholder placeholder : getPlaceholders()) {
            if (placeholderMap.containsKey(placeholder.getName())) {
                if (!placeholderMap.get(placeholder.getName()).isValid(context)) {
                    return false;
                }
            }
        }
        return true;
    }

    public boolean doesRequireRequestResponse(Map<String, IPlaceholderParser> placeholderMap) {
        for (Placeholder placeholder : getPlaceholders()) {
            if (placeholderMap.containsKey(placeholder.getName())) {
                if (placeholderMap.get(placeholder.getName()) instanceof AbstractRequestResponseInfoPlaceholder || placeholderMap.get(placeholder) instanceof AbstractRequestResponsePlaceholder) {
                    return true;
                }
            }
        }
        return false;
    }

    public List<CommandObject.Placeholder> getPlaceholders() {
        if (placeholders == null) {
            // placeholder list might be null, when ContextMenuEntry was loaded from config
            // and no placeholders were defined.
            placeholders = initPlaceholders(Lists.newArrayList());
        }
        return Lists.newArrayList(placeholders);
    }

    @Override
    public String toString() {
        return "CommandObject{" +
                "id='" + id + '\'' +
                ", name='" + name + '\'' +
                ", format='" + format + '\'' +
                ", group='" + group + '\'' +
                ", runtimeBehaviour=" + runtimeBehaviour +
                ", showPreview=" + showPreview +
                ", placeholders=" + placeholders +
                '}';
    }
}
