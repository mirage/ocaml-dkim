(** Email body tokenizer for DKIM canonicalization.

    This module splits a raw email body byte stream into a sequence of tokens:
    literal data, whitespace runs, CRLF line endings, and the end-of-input
    marker. The tokenization is designed to feed directly into the body
    canonicalization logic used by both the simple and relaxed DKIM algorithms.
    Under simple canonicalization the tokens are reassembled as-is; under
    relaxed canonicalization the whitespace tokens are normalized before being
    fed to the hash function. *)

type decode = [ `Data of string | `Await | `End | `CRLF | `Spaces of string ]
(** The type of tokens produced by {!val:decode}.

    - [`Data s] is a chunk of body content that contains no whitespace or
      line-ending characters.
    - [`Spaces s] is a run of space or tab characters.
    - [`CRLF] represents a CR LF line ending.
    - [`Await] means the decoder needs more input; call {!val:src} then
      {!val:decode} again.
    - [`End] signals that the entire body has been consumed. *)

type decoder
(** The state of the body decoder. *)

val src : decoder -> bytes -> int -> int -> unit
(** [src decoder buf off len] provides input bytes to the decoder. The region
    [buf.[off] .. buf.[off+len-1]] is consumed. Passing [len = 0] signals end of
    input. *)

val decode : decoder -> decode
(** [decode decoder] returns the next token from the body stream. *)

val decoder : unit -> decoder
(** [decoder ()] creates a fresh body decoder, ready to receive data via
    {!val:src}. *)
