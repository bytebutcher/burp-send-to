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

    public Config(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        this.callbacks = burpExtender.getCallbacks();
    }

    public void saveSendToTableData(String jsonData) {
        this.callbacks.saveExtensionSetting("SendToTableData", jsonData);
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
            return getRunInTerminalCommand("runInTerminalSettingWindows", "cmd  /c start cmd /K %C");
        } else {
            return getRunInTerminalCommand("runInTerminalSettingUnix", "xterm -hold -e %C");
        }
    }

    private String getRunInTerminalCommand(String label, String defaultValue) {
        String runInTerminalSetting = this.callbacks.loadExtensionSetting(label);
        if (runInTerminalSetting == null || runInTerminalSetting.isEmpty()) {
            runInTerminalSetting = defaultValue;
            this.callbacks.saveExtensionSetting(label, runInTerminalSetting);
        }
        return runInTerminalSetting;
    }

    public void setRunInTerminalCommand(String command) {
        if (OsUtils.isWindows()) {
            this.callbacks.saveExtensionSetting("runInTerminalSettingWindows", command);
        } else {
            this.callbacks.saveExtensionSetting("runInTerminalSettingUnix", command);
        }
    }

}
