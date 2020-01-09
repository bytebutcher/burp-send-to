package net.bytebutcher.burpsendtoextension.models;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import com.google.common.collect.Lists;
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

    public void saveSendToTableData(List<CommandObject> sendToTableData) {
        this.callbacks.saveExtensionSetting("SendToTableData", new Gson().toJson(sendToTableData));
    }

    public List<CommandObject> getSendToTableData() {
        List<CommandObject> commandObjectList = new ArrayList<>();
        try {
            String sendToTableData = this.callbacks.loadExtensionSetting("SendToTableData");
            if (sendToTableData == null || sendToTableData.isEmpty() || "[]".equals(sendToTableData)) {
                if (isFirstStart()) {
                    BurpExtender.printOut("Initializing default table data...");
                    commandObjectList = initializeDefaultSendToTableData();
                }
                return commandObjectList;
            }
            return new Gson().fromJson(sendToTableData, new TypeToken<List<CommandObject>>() {}.getType());
        } catch (Exception e) {
            BurpExtender.printErr("Error retrieving table data!");
            BurpExtender.printErr(e.toString());
            return commandObjectList;
        }
    }

    private List<CommandObject> initializeDefaultSendToTableData() {
        List<CommandObject> commandObjectList = getDefaultSendToTableData();
        saveSendToTableData(commandObjectList);
        unsetFirstStart();
        return commandObjectList;
    }

    public List<CommandObject> getDefaultSendToTableData() {
        String groupFuzz = "fuzz";
        String groupCMS = "cms";
        String groupSQL = "sql";
        String groupSSL = "ssl";
        return Lists.newArrayList(
                new CommandObject("decoder++", "dpp --dialog -f %F", "", false, false, true),
                // cms
                new CommandObject("droopescan", "droopescan scan drupal -u %U -t 10", groupCMS, true, true, false),
                new CommandObject("mooscan", "mooscan -v --url %U", groupCMS, true, true, false),
                new CommandObject("wpscan", "wpscan --url %U --threads 10", groupCMS, true, true, false),
                // fuzz
                new CommandObject("bfac", "bfac --url %U", groupFuzz, true, true, false),
                new CommandObject("gobuster", "gobuster -u %U -s 403,404 -w /usr/share/wfuzz/wordlist/general/common.txt", groupFuzz, true, true, false),
                new CommandObject("nikto", "nikto %U", groupFuzz, true, true, false),
                new CommandObject("wfuzz", "wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt --hc 404,403 %U", groupFuzz, true, true, false),
                // sql
                new CommandObject("sqlmap (GET)", "sqlmap -o -u %U --level=5 --risk=3", groupSQL, true, true, false),
                new CommandObject("sqlmap (POST)", "sqlmap -r %R  --level=5 --risk=3", groupSQL, true, true, false),
                // ssl
                new CommandObject("sslscan", "sslscan %H:%P", groupSSL, true, true, false),
                new CommandObject("sslyze", "sslyze --regular %H:%P", groupSSL, true, true, false),
                new CommandObject("testssl", "testssl.sh %H:%P", groupSSL, true, true, false)
        );
    }

    private boolean isFirstStart() {
        String isFirstStart = this.callbacks.loadExtensionSetting("isFirstStart");
        return isFirstStart == null || "true".equals(isFirstStart);
    }

    private void setFirstStart() {
        this.callbacks.saveExtensionSetting("isFirstStart", null);
    }

    private void unsetFirstStart() {
        this.callbacks.saveExtensionSetting("isFirstStart", "false");
    }

    public void resetRunInTerminalCommand() {
        this.callbacks.saveExtensionSetting("runInTerminalSettingWindows", "cmd  /c start cmd /K %C");
        this.callbacks.saveExtensionSetting("runInTerminalSettingUnix", "xterm -hold -e %C");

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
