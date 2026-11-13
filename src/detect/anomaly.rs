use crate::flows::stats::Ewma;

#[derive(Debug, Clone)]
pub struct AnomalyDetector {
    ewma: Ewma,
    threshold: f64,
}

impl AnomalyDetector {
    pub fn new(alpha: f64, threshold: f64) -> Self {
        Self {
            ewma: Ewma::new(alpha),
            threshold,
        }
    }

    pub fn observe(&mut self, value: f64) -> Option<f64> {
        let z = self.ewma.update(value);
        if z.abs() >= self.threshold {
            Some(z)
        } else {
            None
        }
    }

    pub fn mean(&self) -> f64 {
        self.ewma.mean()
    }
}
