package net.bytebutcher.burpsendtoextension.executioner;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import com.google.common.collect.Lists;
import net.bytebutcher.burpsendtoextension.gui.util.SelectionUtil;
import net.bytebutcher.burpsendtoextension.models.Context;
import net.bytebutcher.burpsendtoextension.utils.OsUtils;
import net.bytebutcher.burpsendtoextension.utils.StringUtils;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.Collectors;

public class CommandExecutioner {

    private String command;
    private final boolean shouldOutputReplaceSelection;
    private final boolean shouldRunInTerminal;
    private final Context context;

    public CommandExecutioner(String command, boolean shouldRunInTerminal, boolean shouldOutputReplaceSelection, Context context) {
        this.command = command;
        this.shouldOutputReplaceSelection = shouldOutputReplaceSelection;
        this.shouldRunInTerminal = shouldRunInTerminal;
        this.context = context;
    }

    public void execute() throws Exception {
        if (command != null) {
            List<String> commandOutput = Lists.newArrayList();
            for (String c : command.split("\n")) {
                ProcessBuilder commandProcessBuilder = getProcessBuilder(c);
                logCommandToBeExecuted(commandProcessBuilder.command().toArray(new String[commandProcessBuilder.command().size()]));
                Process process = commandProcessBuilder.start();
                if (shouldOutputReplaceSelection) {
                    commandOutput.add(StringUtils.fromInputStream(process.getInputStream()));
                }
            }
            if (!commandOutput.isEmpty()) {
                replaceSelectedText(context, commandOutput.stream().collect(Collectors.joining("\n")));
            }
        }
    }

    private ProcessBuilder getProcessBuilder(String command) {
        if (shouldRunInTerminal) {
            return new ProcessBuilder(formatCommandForRunningInTerminal(command));
        } else {
            return new ProcessBuilder(formatCommandForRunningOnOperatingSystem(command));
        }
    }

    private String[] formatCommandForRunningOnOperatingSystem(String command) {
        String[] commandToBeExecuted;
        if (OsUtils.isWindows()) {
            commandToBeExecuted = new String[]{"cmd", "/c", command};
        } else {
            commandToBeExecuted = new String[]{"/bin/bash", "-c", command};
        }
        return commandToBeExecuted;
    }

    private String[] formatCommandForRunningInTerminal(String command) {
        String[] commandToBeExecuted = BurpExtender.getConfig().getRunInTerminalCommand().split(" ");
        for (int i = 0; i < commandToBeExecuted.length; i++) {
            String commandPart = commandToBeExecuted[i];
            if ("%C".equals(commandPart)) {
                commandToBeExecuted[i] = command;
            }
        }
        return commandToBeExecuted;
    }

    private void replaceSelectedText(Context context, String replaceText) throws Exception {
        if (context.getSelectedMessages() != null && context.getSelectedMessages().length > 0) {
            IHttpRequestResponse message = context.getSelectedMessages()[0];
            switch (context.getOrigin()) {
                case HTTP_REQUEST:
                    message.setRequest(SelectionUtil.replaceSelectedText(message.getRequest(), context.getSelectionBounds(), replaceText));
                    break;
                case HTTP_RESPONSE:
                    message.setResponse(SelectionUtil.replaceSelectedText(message.getResponse(), context.getSelectionBounds(), replaceText));
                    break;
            }
        }
    }

    private void logCommandToBeExecuted(String[] commandToBeExecuted) {
        String commandToBeExecutedWithoutControlCharacters = String.join(" ", commandToBeExecuted).replaceAll("[\u0000-\u001f]", "");
        String dateTime = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("uuuu/MM/dd HH:mm:ss"));
        BurpExtender.printOut("[" + dateTime + "] " + commandToBeExecutedWithoutControlCharacters);
        BurpExtender.printOut("----------------------------------------------------------------------");
    }
}
