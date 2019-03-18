package net.bytebutcher.burpsendtoextension.models;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import net.bytebutcher.burpsendtoextension.utils.OsUtils;

import java.util.ArrayList;
import java.util.List;

public class Config {

    private final IBurpExtenderCallbacks callbacks;
    private BurpExtender burpExtender;

    private String runInTerminalSettingUnix;
    private String runInTerminalSettingWindows;
    private String sendToTableData;

    public Config(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        this.callbacks = burpExtender.getCallbacks();
    }

    private void saveSendToTableData(IBurpExtenderCallbacks callbacks) {
        callbacks.saveExtensionSetting("", "");
    }

    public List<CommandObject> getSendToTableData() {
        List<CommandObject> commandObjectList = new ArrayList<>();
        try {
            String sendToTableData = this.callbacks.loadExtensionSetting("SendToTableData");
            if (sendToTableData == null || sendToTableData.isEmpty()) {
                return commandObjectList;
            }
            return new Gson().fromJson(sendToTableData, new TypeToken<List<CommandObject>>() {}.getType());
        } catch (Exception e) {

            return commandObjectList;
        }
    }

    public String getRunInTerminalCommand() {
        if (OsUtils.isWindows()) {
            if (runInTerminalSettingWindows == null) {
                runInTerminalSettingWindows = this.callbacks.loadExtensionSetting("runInTerminalSettingWindows");
                if (runInTerminalSettingWindows == null | runInTerminalSettingWindows.isEmpty()) {
                    runInTerminalSettingWindows = "cmd  /c start cmd /K %C";
                    this.callbacks.saveExtensionSetting("runInTerminalSettingWindows", runInTerminalSettingWindows);
                }
            }
            return runInTerminalSettingWindows;
        } else {
            runInTerminalSettingUnix = this.callbacks.loadExtensionSetting("runInTerminalSettingUnix");
            if (runInTerminalSettingUnix == null || runInTerminalSettingUnix.isEmpty()) {
                runInTerminalSettingUnix = "xterm -hold -e %C";
                this.callbacks.saveExtensionSetting("runInTerminalSettingUnix", runInTerminalSettingUnix);
            }
            return runInTerminalSettingUnix;
        }
    }

    public void setRunInTerminalCommand(String command) {
        if (OsUtils.isWindows()) {
            this.callbacks.saveExtensionSetting("runInTerminalSettingWindows", command);
        } else {
            this.callbacks.saveExtensionSetting("runInTerminalSettingUnix", command);
        }
    }

}
