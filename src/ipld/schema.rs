struct Schema {
    name: String,
    typ: Type,
    repr: Representation,
}

enum Type {
    Kind,
    Struct(Struct),
    Union,
    Enum,
}

struct Struct {
    elements: Vec<Element>,
}

struct Element {
    name: String,
    nullable: bool,
    optional: bool,
}

enum Representation {
    Keyed,
}

// Examples
//
// {Foo:Bar}
//
//
