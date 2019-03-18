package net.bytebutcher.burpsendtoextension.models;

import java.util.UUID;

public class CommandObject {

    private String id = UUID.randomUUID().toString();
    private String name;
    private String command;
    private boolean runInTerminal;
    private boolean showPreview;

    public CommandObject(String name, String command, boolean runInTerminal, boolean showPreview) {
        this.name = name;
        this.command = command;
        this.runInTerminal = runInTerminal;
        this.showPreview = showPreview;
    }

    public CommandObject(String id, String name, String command, boolean runInTerminal, boolean showPreview) {
        this(name, command, runInTerminal, showPreview);
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

    public boolean isRunInTerminal() {
        return this.runInTerminal;
    }

    public boolean shouldShowPreview() {
        return this.showPreview;
    }

    public void setShowPreview(boolean showPreview) {
        this.showPreview = showPreview;
    }
}
