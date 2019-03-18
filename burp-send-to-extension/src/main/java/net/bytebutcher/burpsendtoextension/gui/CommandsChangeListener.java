package net.bytebutcher.burpsendtoextension.gui;

import net.bytebutcher.burpsendtoextension.models.CommandObject;

import java.util.List;

public interface CommandsChangeListener {

    void commandsChanged(List<CommandObject> commandObjects);
}
