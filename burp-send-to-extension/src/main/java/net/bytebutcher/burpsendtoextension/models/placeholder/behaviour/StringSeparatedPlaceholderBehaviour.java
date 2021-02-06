package net.bytebutcher.burpsendtoextension.models.placeholder.behaviour;

public class StringSeparatedPlaceholderBehaviour implements IPlaceholderBehaviour {

    private final String separator;

    public StringSeparatedPlaceholderBehaviour(String separator) {
        this.separator = separator;
    }

    public String getSeparator() {
        return separator;
    }
}
