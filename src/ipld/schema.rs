struct Schema {
    name: String,
    typ: Type,
    mods: Vec<Modifier>,
    repr: Representation,
}

enum Type {
    Null,
    Bool,
    Integer,
    Float,
    Text,
    Bytes,
    List,  // only homogenous value in list
    Map,   // only string keys.
    Union, // as map or varying data-mode-kinds for kinded union
    Tuple, // as map in data-model
    Enum,  // either as string or int.
    Copyy,
}

struct Struct {
    elements: Vec<Element>,
}

enum Modifier {
    Nullable,  // for map-value, list-value and struct fields
    Optional,  // for struct-fields
    Implicite, // for struct-fields
}

enum Representation {
    Keyed,
    Envelope,
    Inline,
}

// Examples
//
// {Foo:Bar}
//
//
