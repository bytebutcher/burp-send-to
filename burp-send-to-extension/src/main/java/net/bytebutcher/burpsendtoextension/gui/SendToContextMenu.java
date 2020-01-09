package net.bytebutcher.burpsendtoextension.gui;

import burp.*;
import com.google.common.collect.*;
import net.bytebutcher.burpsendtoextension.gui.util.DialogUtil;
import net.bytebutcher.burpsendtoextension.models.CommandObject;
import net.bytebutcher.burpsendtoextension.models.Cookie;
import net.bytebutcher.burpsendtoextension.utils.OsUtils;
import net.bytebutcher.burpsendtoextension.utils.StringUtils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

public class SendToContextMenu implements IContextMenuFactory {

    private BurpExtender burpExtender;
    private SendToTableListener sendToTableListener;
    private final List<JMenuItem> sendToMenuBar;
    private final JMenu sendToMenu;
    private IContextMenuInvocation invocation;

    public SendToContextMenu(BurpExtender burpExtender, SendToTableListener sendToTableListener) {
        this.burpExtender = burpExtender;
        this.sendToTableListener = sendToTableListener;
        this.sendToTableListener.registerCommandsChangeLister(new CommandsChangeListener() {
            @Override
            public void commandsChanged(List<CommandObject> commandObjects) {
                refreshSendToMenuBar(commandObjects);
            }
        });
        this.sendToMenuBar = new ArrayList<JMenuItem>();
        this.sendToMenu = new JMenu("Send to...");
        this.sendToMenuBar.add(this.sendToMenu);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        this.invocation = invocation;
        return sendToMenuBar;
    }

    private IRequestInfo getRequestInfo(IHttpRequestResponse req) {
        return burpExtender.getCallbacks().getHelpers().analyzeRequest(req.getHttpService(), req.getRequest());
    }

    private IResponseInfo getResponseInfo(IHttpRequestResponse req) {
        return burpExtender.getCallbacks().getHelpers().analyzeResponse(req.getResponse());
    }

    private String getUrl() {
        String url = "";
        try {
            IRequestInfo iRequestInfo = this.burpExtender.getCallbacks().getHelpers().analyzeRequest(this.invocation.getSelectedMessages()[0]);
            url = iRequestInfo.getUrl().toString();
        } catch (RuntimeException e) {
            BurpExtender.printErr("Error parsing URL!");
        }
        return url;
    }

    private String getHost() {
        String host = "";
        try {
            host = this.invocation.getSelectedMessages()[0].getHttpService().getHost();
        } catch (RuntimeException e) {
            BurpExtender.printErr("Error parsing host!");
        }
        return host;
    }

    private String getPort() {
        String port = "";
        try {
            port = String.valueOf(this.invocation.getSelectedMessages()[0].getHttpService().getPort());
        } catch (RuntimeException e) {
            BurpExtender.printErr("Error parsing port!");
        }
        return port;
    }

    private String getSelectedText() {
        String selectedText = "";
        try {
            int[] selectionBounds = this.invocation.getSelectionBounds();
            IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
            if (selectionBounds != null && selectedMessages != null) {
                byte iContext = invocation.getInvocationContext();
                byte[] requestResponse = getRequestResponse(iContext, invocation.getSelectedMessages()[0]);
                if (requestResponse != null) {
                    selectedText = new String(requestResponse).substring(selectionBounds[0], selectionBounds[1]);
                } else {
                    BurpExtender.printErr("Error parsing selected text! No request/response found!");
                }
            } else {
                BurpExtender.printErr("Error parsing selected text! No selected message and/or selection bounds!");
            }
        } catch (RuntimeException e) {
            BurpExtender.printErr("Error parsing selected text!");
        }
        return selectedText;
    }

    private String getRequestResponse() {
        String requestResponseString = "";
        try {
            byte iContext = invocation.getInvocationContext();
            byte[] requestResponse = getRequestResponse(iContext, invocation.getSelectedMessages()[0]);
            requestResponseString = (requestResponse == null) ? "" : new String(requestResponse);
        } catch (RuntimeException e) {
            BurpExtender.printErr("Error parsing focused request/response!");
        }
        return requestResponseString;
    }

    private byte[] getRequestResponse(byte iContext, IHttpRequestResponse message) {
        if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
                || iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
            // HTTP-Request
            return message.getRequest();
        } else if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE
                || iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {
            // HTTP-Response
            return message.getResponse();
        } else {
            // Unknown
            return null;
        }
    }

    private String getMethod() {
        String method = "";
        try {
            IRequestInfo iRequestInfo = this.burpExtender.getCallbacks().getHelpers().analyzeRequest(this.invocation.getSelectedMessages()[0]);
            method = iRequestInfo.getMethod();
        } catch (RuntimeException e) {
            BurpExtender.printErr("Error parsing method!");
        }
        return method;
    }

    private String getCookies() {
        String cookies = "";
        try {
            List<ICookie> cookieList = Lists.newArrayList();
            String cookieHeaderPrefix = "cookie: ";
            IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
            if (selectedMessages != null) {
                IHttpRequestResponse message = selectedMessages[0];
                List<String> cookieHeaders = getRequestInfo(message).getHeaders().stream().filter(s -> s.toLowerCase().startsWith(cookieHeaderPrefix)).collect(Collectors.toList());
                boolean hasCookieHeader = !cookieHeaders.isEmpty();
                cookieList = Lists.newArrayList();
                if (hasCookieHeader) {
                    for (String cookieHeader : cookieHeaders) {
                        cookieList.addAll(Cookie.parseRequestCookies(cookieHeader.substring(cookieHeaderPrefix.length() - 1)));
                    }
                }
            }
            cookies = cookieList.stream().map(iCookie -> iCookie.getName() + "=" + iCookie.getValue()).collect(Collectors.joining(","));
        } catch (RuntimeException e) {
            BurpExtender.printErr("Error parsing cookies!");
        }
        return cookies;
    }

    private String getUrlPath() {
        String urlPath = "";
        try {
            IRequestInfo iRequestInfo = this.burpExtender.getCallbacks().getHelpers().analyzeRequest(this.invocation.getSelectedMessages()[0]);
            if (iRequestInfo.getUrl().getPath() != null) {
                urlPath = iRequestInfo.getUrl().getPath();
            }
        } catch (RuntimeException e) {
            BurpExtender.printErr("Error parsing url path!");
        }
        return urlPath;
    }

    private String getUrlQuery() {
        String urlQuery = "";
        try {
            IRequestInfo iRequestInfo = this.burpExtender.getCallbacks().getHelpers().analyzeRequest(this.invocation.getSelectedMessages()[0]);
            if (iRequestInfo.getUrl().getQuery() != null) {
                urlQuery = iRequestInfo.getUrl().getQuery();
            }
        } catch (RuntimeException e) {
            BurpExtender.printErr("Error parsing url query!");
        }
        return urlQuery;
    }

    private String getProtocol() {
        String protocol = "";
        try {
            protocol = String.valueOf(this.invocation.getSelectedMessages()[0].getHttpService().getProtocol());
        } catch (RuntimeException e) {
            BurpExtender.printErr("Error parsing protocol!");
        }
        return protocol;
    }

    public String getBody() {
        String body = "";
        try {
            byte iContext = invocation.getInvocationContext();
            IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
            if (selectedMessages != null) {
                IHttpRequestResponse message = selectedMessages[0];
                int bodyOffset = getBodyOffset(iContext, message);
                if (bodyOffset != -1) {
                    byte[] requestResponse = getRequestResponse(iContext, message);
                    if (requestResponse != null) {
                        body = new String(Arrays.copyOfRange(requestResponse, bodyOffset, requestResponse.length));
                    } else {
                        BurpExtender.printErr("Error parsing body! No request/response found!");
                    }
                } else {
                    BurpExtender.printErr("Error parsing body! Parsing body offset failed!");
                }
            } else {
                BurpExtender.printErr("Error parsing body! No selected message!");
            }
        } catch (RuntimeException e) {
            BurpExtender.printErr("Error parsing body!");
        }
        return body;
    }

    private int getBodyOffset(byte iContext, IHttpRequestResponse message) {
        int bodyOffset = -1;
        if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
                || iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
            // HTTP-Request
            bodyOffset = getRequestInfo(message).getBodyOffset();
        } else if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE
                || iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {
            // HTTP-Response
            bodyOffset = getResponseInfo(message).getBodyOffset();
        }
        return bodyOffset;
    }

    private void replaceSelectedText(String replaceText) {
        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
            int[] bounds = invocation.getSelectionBounds();
            byte[] message = invocation.getSelectedMessages()[0].getRequest();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            try {
                outputStream.write(Arrays.copyOfRange(message, 0, bounds[0]));
                outputStream.write(replaceText.getBytes());
                outputStream.write(Arrays.copyOfRange(message, bounds[1], message.length));
                outputStream.flush();
                invocation.getSelectedMessages()[0].setRequest(outputStream.toByteArray());
            } catch (IOException e) {
                burpExtender.getCallbacks().printError("Error during replacing selection with output: " + e.toString());
            }
        }
    }

    public void refreshSendToMenuBar(final List<CommandObject> commandObjects) {
        sendToMenu.removeAll();
        sendToMenu.add(new JMenuItem(new AbstractAction("Custom command...") {
            @Override
            public void actionPerformed(ActionEvent e) {
                SendToAddDialog addDialog = new SendToAddDialog(
                        burpExtender.getParent(),
                        "Add and run custom command...",
                        commandObjects
                );
                if (addDialog.run()) {
                    CommandObject commandObject = addDialog.getCommandObject();
                    sendToTableListener.onAddButtonClick(e, commandObject);
                    String result = runCommandObject(commandObject);
                    if (commandObject.shouldOutputReplaceSelection() && result != null) {
                        replaceSelectedText(result);
                    }
                }
            }
        }));
        if (commandObjects.size() > 0) {
            sendToMenu.addSeparator();
            HashMap<String, java.util.List<CommandObject>> groupedCommandObjects = Maps.newLinkedHashMap();
            boolean hasEmptyGroup = false;
            for (final CommandObject commandObject : commandObjects) {
                String group = commandObject.getGroup();
                if (group.isEmpty()) {
                    sendToMenu.add(newCommandMenuItem(commandObject));
                    hasEmptyGroup = true;
                    continue;
                }
                if (!groupedCommandObjects.containsKey(group)) {
                    groupedCommandObjects.put(group, Lists.newArrayList());
                }
                groupedCommandObjects.get(group).add(commandObject);
            }
            if (hasEmptyGroup && !groupedCommandObjects.isEmpty()) {
                sendToMenu.addSeparator();
            }
            for (String group : groupedCommandObjects.keySet()) {
                JMenu menuItem = new JMenu(group);
                for (CommandObject commandObject : groupedCommandObjects.get(group)) {
                    menuItem.add(newCommandMenuItem(commandObject));
                }
                sendToMenu.add(menuItem);
            }
        }
        sendToMenuBar.add(sendToMenu);
    }

    private JMenuItem newCommandMenuItem(CommandObject commandObject) {
        return new JMenuItem(new AbstractAction(commandObject.getName()) {
            @Override
            public void actionPerformed(ActionEvent e) {
                String result = runCommandObject(commandObject);
                if (commandObject.shouldOutputReplaceSelection() && result != null) {
                    replaceSelectedText(result);
                }
            }
        });
    }

    private Set<String> getCommandNames(List<CommandObject> commandObjects) {
        Set<String> names = new HashSet<String>();
        for (CommandObject commandObject : commandObjects) {
            names.add(commandObject.getName());
        }
        return names;
    }

    private String runCommandObject(CommandObject commandObject) {
        try {
            String[] commandToBeExecuted = getCommandToBeExecuted(commandObject);
            if (commandToBeExecuted == null) {
                return null;
            }

            logCommandToBeExecuted(commandToBeExecuted);
            Process process = new ProcessBuilder(commandToBeExecuted).start();
            return StringUtils.fromInputStream(process.getInputStream());
        } catch (Exception e) {
            DialogUtil.showErrorDialog(
                    burpExtender.getParent(),
                    "Error during command execution!",
                    "<html><p>There was an unknown error during command execution!</p>" +
                            "<p>For more information check out the \"Send to\" extension error log!</p></html>"
            );
            BurpExtender.printErr("Error during command execution: " + e);
            BurpExtender.printErr(stackTraceToString(e));
            return null;
        }
    }

    private String stackTraceToString(Exception e) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        e.printStackTrace(pw);
        return sw.toString();
    }

    private String[] getCommandToBeExecuted(CommandObject commandObject) throws IOException {
        return formatCommand(commandObject);
    }

    private String[] formatCommand(CommandObject commandObject) throws IOException {
        String[] commandToBeExecuted;
        String command = formatCommandPattern(commandObject.getCommand());

        if (commandObject.shouldShowPreview()) {
            SendToPreviewDialog previewDialog = new SendToPreviewDialog(
                    burpExtender.getParent(),
                    "Execute command?",
                    commandObject.getId(),
                    command,
                    sendToTableListener
            );
            if (!previewDialog.run()) {
                return null;
            }
            command = previewDialog.getCommand();
        }

        if (commandObject.isRunInTerminal()) {
            commandToBeExecuted = formatCommandForRunningInTerminal(command);
        } else {
            commandToBeExecuted = formatCommandRunningOnOperatingSystem(command);
        }
        return commandToBeExecuted;
    }

    private String[] formatCommandRunningOnOperatingSystem(String command) {
        String[] commandToBeExecuted;
        if (OsUtils.isWindows()) {
            commandToBeExecuted = new String[]{"cmd", "/c", command};
        } else {
            commandToBeExecuted = new String[]{"/bin/bash", "-c", command};
        }
        return commandToBeExecuted;
    }

    private String formatCommandPattern(String command) throws IOException {
        if (command.contains("%S")) {
            command = command.replace("%S", "'" + StringUtils.shellEscape(this.getSelectedText()) + "'");
        }
        if (command.contains("%H")) {
            command = command.replace("%H", "'" + StringUtils.shellEscape(getHost()) +  "'");
        }
        if (command.contains("%P")) {
            command = command.replace("%P", getPort());
        }
        if (command.contains("%T")) {
            command = command.replace("%T", "'" + StringUtils.shellEscape(getProtocol()) +  "'");
        }
        if (command.contains("%U")) {
            command = command.replace("%U", "'" + StringUtils.shellEscape(getUrl()) +  "'");
        }
        if (command.contains("%A")) {
            command = command.replace("%A", "'" + StringUtils.shellEscape(getUrlPath()) +  "'");
        }
        if (command.contains("%Q")) {
            command = command.replace("%Q", "'" + StringUtils.shellEscape(getUrlQuery()) +  "'");
        }
        if (command.contains("%C")) {
            command = command.replace("%C",  "'" + StringUtils.shellEscape(getCookies()) +  "'");
        }
        if (command.contains("%M")) {
            command = command.replace("%M", "'" + StringUtils.shellEscape(getMethod()) +  "'");
        }
        if (command.contains("%B")) {
            File tmp = writeTextToTemporaryFile(getBody());
            command = command.replace("%B", tmp.getAbsolutePath());
        }
        if (command.contains("%R")) {
            File tmp = writeTextToTemporaryFile(getRequestResponse());
            command = command.replace("%R", tmp.getAbsolutePath());
        }
        if (command.contains("%F")) {
            File tmp = writeTextToTemporaryFile(getSelectedText());
            command = command.replace("%F", tmp.getAbsolutePath());
        }
        return command;
    }

    private File writeTextToTemporaryFile(String input) throws IOException {
        if (input == null) {
            input = "";
        }
        File tmp = File.createTempFile("burp_", ".snd");
        try {
            PrintWriter out = new PrintWriter(tmp.getPath());
            out.write(input);
            out.flush();
        } catch (RuntimeException e) {
            BurpExtender.printErr("Error writing to temporary file!");
        }
        return tmp;
    }

    private String[] formatCommandForRunningInTerminal(String command) throws IOException {
        String[] commandToBeExecuted = this.burpExtender.getConfig().getRunInTerminalCommand().split(" ");
        for (int i = 0; i < commandToBeExecuted.length; i++) {
            String commandPart = commandToBeExecuted[i];
            if ("%C".equals(commandPart)) {
                commandToBeExecuted[i] = command;
            }
        }
        return commandToBeExecuted;
    }

    private void logCommandToBeExecuted(String[] commandToBeExecuted) {
        String commandToBeExecutedWithoutControlCharacters = String.join(" ", commandToBeExecuted).replaceAll("[\u0000-\u001f]", "");
        String dateTime = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("uuuu/MM/dd HH:mm:ss"));
        BurpExtender.printOut("[" + dateTime + "] " + commandToBeExecutedWithoutControlCharacters);
        BurpExtender.printOut("----------------------------------------------------------------------");
    }
}
