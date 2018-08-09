use errors::*;

fn deserialize_suffix( n: &str) -> Result<u64> 
{
    Ok(match n {
        "Ki" => 1024,
        "Mi" => 1024*1024,
        "Gi" => 1024*1024*1024,
        "K" => 1000,
        "M" => 1000*1000,
        "G" => 1000*1000*1000,
        "" => 1,
        n => return Err(
                ScalpelError::ArgumentError
                .context(format!("Bad Suffix: {}", n))
                .into(),
            )
    })
}


pub fn serialize_cmd_opt(flag: String) -> Result<u64> {
    
    let suffix: u64 = deserialize_suffix(flag.trim_matches(char::is_numeric))?;
    let val: u64 = flag.trim_matches(char::is_alphabetic).parse()?;

    Ok(val * suffix)
}