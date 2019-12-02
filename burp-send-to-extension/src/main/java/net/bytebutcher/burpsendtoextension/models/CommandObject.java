package net.bytebutcher.burpsendtoextension.models;

import java.util.Objects;
import java.util.UUID;

public class CommandObject {

    private String id = UUID.randomUUID().toString();
    private String name;
    private String command;
    private String group;
    private boolean runInTerminal;
    private boolean showPreview;
    private boolean outputReplaceSelection;

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

    public void setName(String name) {
        this.name = name;
    }

    public String getCommand() {
        return this.command;
    }

    public String getGroup() {
        return group;
    }

    public void setGroup(String group) {
        this.group = group;
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

    public void setOutputReplaceSelection(boolean outputReplaceSelection) {
        this.outputReplaceSelection = outputReplaceSelection;
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

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
