pub mod soundness {
    pub enum Soundness {
        Exact,
        MayOver,
    }
    pub trait SoundnessTagged {
        fn soundness(&self) -> Soundness;
    }
}
