/// Shared trait for all hashing algorithms available.
pub trait Hasher {
    /// The needed parameters.
    ///
    /// You should store this type inside your encryption algorithm
    type Params: Send + 'static;

    /// Feed the hasher a single chunk of data.
    ///
    /// It's up to the actual hashing implementation to see how to incorporate the data, generally
    /// through some sort of rolling implementation, or updating state machine.
    fn read(&mut self, chunk: Vec<u8>);

    /// Reset this hasher.
    ///
    /// Doing this will restore any state that was accumulated from [`Hasher::read`] calls.
    fn reset(&mut self);

    /// Get the final digest of the hashed data.
    ///
    /// It's up to the caller to ensure all required data has been fed into the hasher before
    /// retreiving the [`Self::digest`].
    fn digest(&self) -> String;

    /// Get the final digest of the hashed data, as a [`Vec<u8>`].
    ///
    /// It's up to the caller to ensure all required data has been fed into the hasher before
    /// retreiving the [`Self::digest`].
    fn digest_bytes(&self) -> Vec<u8>;
}
