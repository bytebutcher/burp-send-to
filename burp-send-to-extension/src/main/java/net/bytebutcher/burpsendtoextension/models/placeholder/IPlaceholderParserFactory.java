package net.bytebutcher.burpsendtoextension.models.placeholder;

import burp.RequestResponseHolder;

public interface IPlaceholderParserFactory {

    IPlaceholderParser createParser(RequestResponseHolder requestResponseHolder);

}
