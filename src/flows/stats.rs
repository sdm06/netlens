#[derive(Debug, Clone, Copy)]
pub struct Ewma {
    mean: f64,
    variance: f64,
    alpha: f64,
    initialized: bool,
}

impl Ewma {
    pub fn new(alpha: f64) -> Self {
        Self {
            mean: 0.0,
            variance: 0.0,
            alpha: alpha.clamp(0.001, 0.999),
            initialized: false,
        }
    }

    pub fn update(&mut self, value: f64) -> f64 {
        if !self.initialized {
            self.mean = value;
            self.initialized = true;
            return 0.0;
        }
        let delta = value - self.mean;
        self.mean += self.alpha * delta;
        self.variance = (1.0 - self.alpha) * (self.variance + self.alpha * delta * delta);
        if self.variance <= f64::EPSILON {
            0.0
        } else {
            delta / self.variance.sqrt()
        }
    }

    pub fn mean(&self) -> f64 {
        self.mean
    }

    pub fn stddev(&self) -> f64 {
        self.variance.sqrt()
    }
}
