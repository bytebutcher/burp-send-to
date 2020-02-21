package net.bytebutcher.burpsendtoextension.models;

public enum ERuntimeBehaviour {

    RUN_IN_BACKGROUND("Run in Background"),
    RUN_IN_TERMINAL("Run in Terminal"),
    OUTPUT_SHOULD_REPLACE_SELECTION("Output should replace Selection");

    private String alternateName;

    ERuntimeBehaviour(String alternateName) {
        this.alternateName = alternateName;
    }

    public String alternateName() {
        return this.alternateName;
    }

    public static ERuntimeBehaviour getEnum(String name) {
        for (ERuntimeBehaviour value : ERuntimeBehaviour.values()) {
            if (value.name().equals(name) || value.alternateName().equals(name)) {
                return value;
            }
        }
        throw new IllegalArgumentException();
    }

}
