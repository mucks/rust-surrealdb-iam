pub fn jwt_secret() -> String {
    std::env::var("JWT_SECRET").expect("NO JWT_SECRET SET")
}

pub fn validate_envs() {
    jwt_secret();
}
