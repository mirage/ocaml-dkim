type 'a t = 'a option

let some x = Some x

let map f = function
  | Some x -> Some (f x)
  | None -> None

let value ~default = function
  | Some x -> x
  | None -> default

let bind x f = match x with Some x -> f x | None -> None

let (>>=) = bind
let (>>|) x f = map f x
