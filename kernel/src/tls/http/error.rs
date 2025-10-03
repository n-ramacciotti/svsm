#[derive(Clone, Copy, Debug)]
pub enum HttpError {
    GenericError,
    MissingHeader(&'static str),
}
