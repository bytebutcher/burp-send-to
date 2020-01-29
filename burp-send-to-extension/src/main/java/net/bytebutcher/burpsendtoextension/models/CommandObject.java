package net.bytebutcher.burpsendtoextension.models;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.gson.annotations.SerializedName;
import net.bytebutcher.burpsendtoextension.models.placeholder.AbstractRequestResponseInfoPlaceholder;
import net.bytebutcher.burpsendtoextension.models.placeholder.AbstractRequestResponsePlaceholder;
import net.bytebutcher.burpsendtoextension.models.placeholder.IPlaceholder;
import net.bytebutcher.burpsendtoextension.utils.StringUtils;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class CommandObject {

    private String id = UUID.randomUUID().toString();
    private String name;
    @SerializedName(value="format", alternate={"command"}) // Changed field name from "command" to "format" in version 1.1
    private String format;
    private String group;
    private boolean runInTerminal;
    private boolean showPreview;
    private boolean outputReplaceSelection;
    private Set<String> internalPlaceHolders;

    public CommandObject(String name, String format, String group, boolean runInTerminal, boolean showPreview, boolean outputReplaceSelection) {
        this.name = name;
        this.format = format;
        this.group = group;
        this.runInTerminal = runInTerminal;
        this.showPreview = showPreview;
        this.outputReplaceSelection = outputReplaceSelection;
    }

    public CommandObject(String id, String name, String format, String group, boolean runInTerminal, boolean showPreview, boolean outputReplaceSelection) {
        this(name, format, group, runInTerminal, showPreview, outputReplaceSelection);
        this.id = id;
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

    public boolean shouldRunInTerminal() {
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

    public boolean shouldRunInBackground() {
        return !runInTerminal && !outputReplaceSelection;
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
            if (getFormat() != null && !getFormat().isEmpty()) {
                Matcher m = Pattern.compile("(\\%[A-Z])").matcher(getFormat());
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

    public List<Map<String, IPlaceholder>> getValid(List<Map<String, IPlaceholder>> placeholders, Context context) {
        List<Map<String, IPlaceholder>> validItems = Lists.newArrayList();
        for (Map<String, IPlaceholder> placeholderMap : placeholders) {
            if (isValid(placeholderMap, context)) {
                validItems.add(placeholderMap);
            }
        }
        return validItems;
    }

    private boolean isValid(Map<String, IPlaceholder> placeholderMap, Context context) {
        for (String placeholder : getInternalPlaceHolders()) {
            if (placeholderMap.containsKey(placeholder)) {
                if (!placeholderMap.get(placeholder).isValid(context)) {
                    return false;
                }
            }
        }
        return true;
    }

    public boolean doesRequireRequestResponse(Map<String, IPlaceholder> placeholderMap) {
        for (String placeholder : getInternalPlaceHolders()) {
            if (placeholderMap.containsKey(placeholder)) {
                if (placeholderMap.get(placeholder) instanceof AbstractRequestResponseInfoPlaceholder || placeholderMap.get(placeholder) instanceof AbstractRequestResponsePlaceholder) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Returns the command while all placeholders are replaced with their associated value as String.
     * @throws Exception when retrieving/replacing a placeholder failed.
     */
    public String getCommand(List<Map<String, IPlaceholder>> placeholderMap, Context context) throws Exception {
        try {
            String command = getFormat();
            for (String internalPlaceHolder : getInternalPlaceHolders()) {
                String value = getValid(placeholderMap, context).stream().map(m -> m.get(internalPlaceHolder)).map(iPlaceholder -> iPlaceholder.getValue(context)).collect(Collectors.joining(","));
                boolean doesRequireShellEscape = placeholderMap.get(0).get(internalPlaceHolder).doesRequireShellEscape();
                command = command.replace(internalPlaceHolder, doesRequireShellEscape ? "'" + StringUtils.shellEscape(value) + "'" : value);
            }
            return command;
        } catch (RuntimeException e) {
            // Rethrow from unchecked to checked exception. We only deal with RuntimeException here, since streams
            // (here: placeholderMap.stream()) does not handle checked exceptions well.
            throw new Exception(e);
        }
    }

}
