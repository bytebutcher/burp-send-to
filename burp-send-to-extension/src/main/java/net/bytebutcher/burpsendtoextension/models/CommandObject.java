package net.bytebutcher.burpsendtoextension.models;

import com.google.common.collect.Sets;
import net.bytebutcher.burpsendtoextension.models.placeholder.IPlaceholder;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CommandObject {

    private String id = UUID.randomUUID().toString();
    private String name;
    private String command;
    private String group;
    private boolean runInTerminal;
    private boolean showPreview;
    private boolean outputReplaceSelection;
    private Set<String> internalPlaceHolders;

    public CommandObject(String name, String command, String group, boolean runInTerminal, boolean showPreview, boolean outputReplaceSelection) {
        this.name = name;
        this.command = command;
        this.group = group;
        this.runInTerminal = runInTerminal;
        this.showPreview = showPreview;
        this.outputReplaceSelection = outputReplaceSelection;
    }

    public CommandObject(String id, String name, String command, String group, boolean runInTerminal, boolean showPreview, boolean outputReplaceSelection) {
        this(name, command, group, runInTerminal, showPreview, outputReplaceSelection);
        this.id = id;
    }

    public String getId() { return this.id; }

    public String getName() {
        return this.name;
    }

    public String getCommand() {
        return this.command;
    }

    public String getGroup() {
        return group;
    }

    public boolean isRunInTerminal() {
        return this.runInTerminal;
    }

    public boolean shouldShowPreview() {
        return this.showPreview;
    }

    public void setShowPreview(boolean showPreview) {
        this.showPreview = showPreview;
    }

    public boolean shouldOutputReplaceSelection() {
        return outputReplaceSelection;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CommandObject that = (CommandObject) o;
        return id.equals(that.id);
    }

    private Set<String> getInternalPlaceHolders() {
        if (internalPlaceHolders == null) {
            internalPlaceHolders = Sets.newHashSet();
            if (getCommand() != null && !getCommand().isEmpty()) {
                Matcher m = Pattern.compile("(\\%[A-Z])").matcher(getCommand());
                while (m.find()) {
                    internalPlaceHolders.add(m.group(1));
                }
            }
        }
        return internalPlaceHolders;
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    public boolean isValid(List<Map<String, IPlaceholder>> placeholders) {
        for (Map<String, IPlaceholder> placeholderMap : placeholders) {
            for (String placeholder : getInternalPlaceHolders()) {
                if (placeholderMap.containsKey(placeholder)) {
                    if (!placeholderMap.get(placeholder).isValid()) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    /**
     * Returns the command while all placeholders are replaced with their associated value.
     * @throws Exception when retrieving/replacing a placeholder failed.
     */
    public String getFormattedCommand(Map<String, IPlaceholder> placeholderMap) throws Exception {
        String originalCommand = getCommand();
        for (String internalPlaceHolder : getInternalPlaceHolders()) {
            originalCommand = placeholderMap.get(internalPlaceHolder).replace(originalCommand);
        }
        return originalCommand;
    }
}
