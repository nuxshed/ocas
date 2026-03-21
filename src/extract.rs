use crate::error::AppError;

pub struct EmailInfo {
    pub usertype: String,
    pub rollnum: Option<String>,
    pub batch: Option<i32>,
}

/// parses an iiith email and extracts user type and student metadata
pub fn parseemail(email: &str) -> Result<EmailInfo, AppError> {
    let domain = email
        .rsplit_once('@')
        .map(|(_, d)| d)
        .ok_or_else(|| AppError::BadRequest("invalid email".into()))?;

    match domain {
        "students.iiit.ac.in" => {
            let local = email.split('@').next().unwrap();
            let rollnum = local
                .rsplit('.')
                .next()
                .ok_or_else(|| AppError::BadRequest("cannot parse roll number".into()))?;

            let batch: i32 = rollnum
                .get(..4)
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| {
                    AppError::BadRequest("cannot parse batch from roll number".into())
                })?;

            Ok(EmailInfo {
                usertype: "student".into(),
                rollnum: Some(rollnum.to_string()),
                batch: Some(batch),
            })
        }
        "research.iiit.ac.in" => Ok(EmailInfo {
            usertype: "student".into(),
            rollnum: None,
            batch: None,
        }),
        "iiit.ac.in" => Ok(EmailInfo {
            usertype: "faculty".into(),
            rollnum: None,
            batch: None,
        }),
        _ => Err(AppError::BadRequest(
            "email must be an iiit.ac.in address".into(),
        )),
    }
}
