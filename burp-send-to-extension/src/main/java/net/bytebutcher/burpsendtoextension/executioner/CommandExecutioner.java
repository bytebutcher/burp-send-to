package net.bytebutcher.burpsendtoextension.executioner;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import com.google.common.collect.Lists;
import net.bytebutcher.burpsendtoextension.gui.util.SelectionUtil;
import net.bytebutcher.burpsendtoextension.models.Context;
import net.bytebutcher.burpsendtoextension.models.ERunInTerminalBehaviour;
import net.bytebutcher.burpsendtoextension.utils.OsUtils;
import net.bytebutcher.burpsendtoextension.utils.StringUtils;

import java.io.IOException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class CommandExecutioner {

    private final ERunInTerminalBehaviour runInTerminalBehaviour;
    private final boolean shouldOutputReplaceSelection;
    private final Context context;

    public CommandExecutioner(boolean shouldOutputReplaceSelection, Context context) {
        this.runInTerminalBehaviour = null;
        this.shouldOutputReplaceSelection = shouldOutputReplaceSelection;
        this.context = context;
    }

    public CommandExecutioner(ERunInTerminalBehaviour runInTerminalBehaviour, boolean shouldOutputReplaceSelection, Context context) {
        this.runInTerminalBehaviour = runInTerminalBehaviour;
        this.shouldOutputReplaceSelection = shouldOutputReplaceSelection;
        this.context = context;
    }

    public void execute(String commands) throws Exception {
        if (commands != null) {
            List<String> commandOutput = Lists.newArrayList();
            if (runInTerminalBehaviour != null && runInTerminalBehaviour == ERunInTerminalBehaviour.RUN_IN_SINGLE_TERMINAL) {
                // Run commands sequential within terminal
                String command = Arrays.stream(commands.split("\n")).collect(Collectors.joining(" ; "));
                execute(command, commandOutput);
            } else {
                // Run commands in parallel (within separate terminals or in background)
                for (String command : commands.split("\n")) {
                    execute(command, commandOutput);
                }
            }
            if (!commandOutput.isEmpty()) {
                replaceSelectedText(context, commandOutput.stream().collect(Collectors.joining("\n")));
            }
        }
    }

    private void execute(String command, List<String> commandOutput) throws IOException {
        ProcessBuilder commandProcessBuilder = getProcessBuilder(command);
        logCommandToBeExecuted(commandProcessBuilder.command().toArray(new String[commandProcessBuilder.command().size()]));
        Process process = commandProcessBuilder.start();
        if (shouldOutputReplaceSelection) {
            commandOutput.add(StringUtils.fromInputStream(process.getInputStream()));
        }
    }

    private ProcessBuilder getProcessBuilder(String command) {
        if (runInTerminalBehaviour != null) {
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
