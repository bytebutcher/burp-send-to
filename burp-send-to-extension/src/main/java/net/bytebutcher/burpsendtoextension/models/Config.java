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
    private String version = "1.0";

    public Config(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        this.callbacks = burpExtender.getCallbacks();
        refreshVersion();
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
        String groupOther = "other";
        return Lists.newArrayList(
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
                new CommandObject("testssl", "testssl.sh %H:%P", groupSSL, true, true, false),
                // other
                new CommandObject("Host (%H)", "echo %H", groupOther, false, true, true),
                new CommandObject("Port (%P)", "echo %P", groupOther, false, true, true),
                new CommandObject("Protocol (%T)", "echo %T", groupOther, false, true, true),
                new CommandObject("URL (%U)", "echo %U", groupOther, false, true, true),
                new CommandObject("URL Path (%A)", "echo %A", groupOther, false, true, true),
                new CommandObject("URL Query (%Q)", "echo %Q", groupOther, false, true, true),
                new CommandObject("Cookies (%C)", "echo %C", groupOther, false, true, true),
                new CommandObject("HTTP Method (%M)", "echo %M", groupOther, false, true, true),
                new CommandObject("Selected text (%S)", "echo %S", groupOther, false, true, true),
                new CommandObject("Selected text as file (%F)", "echo %F && cat %F", groupOther, false, true, false),
                new CommandObject("Selected request/response as file (%R)", "echo %R && cat %R", groupOther, false, true, false),
                new CommandObject("Headers of selected request/response as file (%E)", "echo %E && cat %E", groupOther, false, true, false),
                new CommandObject("Body of selected request/response as file (%B)", "echo %B && cat %B", groupOther, false, true, false)
        );
    }

    private void refreshVersion() {
        if (!this.version.equals(this.callbacks.loadExtensionSetting("version"))) {
            this.callbacks.saveExtensionSetting("version", version);
            setFirstStart();
        }
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
