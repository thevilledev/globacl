impl BenchConfig {
    fn default() -> Self {
        Self {
            entries: 100_000,
            lookups: 1_000_000,
            shard_count: DEFAULT_SHARD_COUNT,
            positive_pool: 100_000,
            negative_pool: 100_000,
            sample_limit: 1_000_000,
        }
    }

    fn ci() -> Self {
        Self {
            entries: 50_000,
            lookups: 100_000,
            shard_count: DEFAULT_SHARD_COUNT,
            positive_pool: 50_000,
            negative_pool: 50_000,
            sample_limit: 20_000,
        }
    }

    fn from_env() -> Result<CliAction, String> {
        let mut config = Self::default();
        let mut positional = Vec::new();
        let mut args = env::args().skip(1);

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-h" | "--help" => return Ok(CliAction::Help),
                "--ci" => config = Self::ci(),
                "--entries" => config.entries = parse_next(&mut args, "--entries")?,
                "--lookups" => config.lookups = parse_next(&mut args, "--lookups")?,
                "--shards" | "--shard-count" => {
                    config.shard_count = parse_next(&mut args, "--shards")?
                }
                "--positive-pool" => {
                    config.positive_pool = parse_next(&mut args, "--positive-pool")?
                }
                "--negative-pool" => {
                    config.negative_pool = parse_next(&mut args, "--negative-pool")?
                }
                "--sample-limit" => config.sample_limit = parse_next(&mut args, "--sample-limit")?,
                value if value.starts_with("--entries=") => {
                    config.entries = parse_inline(value, "--entries=")?
                }
                value if value.starts_with("--lookups=") => {
                    config.lookups = parse_inline(value, "--lookups=")?
                }
                value if value.starts_with("--shards=") => {
                    config.shard_count = parse_inline(value, "--shards=")?
                }
                value if value.starts_with("--shard-count=") => {
                    config.shard_count = parse_inline(value, "--shard-count=")?
                }
                value if value.starts_with("--positive-pool=") => {
                    config.positive_pool = parse_inline(value, "--positive-pool=")?
                }
                value if value.starts_with("--negative-pool=") => {
                    config.negative_pool = parse_inline(value, "--negative-pool=")?
                }
                value if value.starts_with("--sample-limit=") => {
                    config.sample_limit = parse_inline(value, "--sample-limit=")?
                }
                value if value.starts_with("--") => {
                    return Err(format!("unknown argument: {value}"));
                }
                value => positional.push(value.to_owned()),
            }
        }

        if positional.len() > 3 {
            return Err("too many positional arguments".to_owned());
        }
        if let Some(value) = positional.first() {
            config.entries = parse_value(value, "entry_count")?;
        }
        if let Some(value) = positional.get(1) {
            config.lookups = parse_value(value, "lookup_count")?;
        }
        if let Some(value) = positional.get(2) {
            config.shard_count = parse_value(value, "shard_count")?;
        }
        if config.shard_count == 0 {
            return Err("shard_count must be greater than zero".to_owned());
        }

        Ok(CliAction::Run(config))
    }
}

impl LookupStats {
    fn empty() -> Self {
        Self {
            denies: 0,
            elapsed: Duration::ZERO,
            samples_ns: Vec::new(),
        }
    }
}

fn parse_next<T>(args: &mut impl Iterator<Item = String>, name: &str) -> Result<T, String>
where
    T: FromStr,
{
    let value = args
        .next()
        .ok_or_else(|| format!("missing value for {name}"))?;
    parse_value(&value, name)
}

fn parse_inline<T>(arg: &str, prefix: &str) -> Result<T, String>
where
    T: FromStr,
{
    parse_value(&arg[prefix.len()..], prefix.trim_end_matches('='))
}

fn parse_value<T>(value: &str, name: &str) -> Result<T, String>
where
    T: FromStr,
{
    value
        .parse::<T>()
        .map_err(|_| format!("invalid value for {name}: {value}"))
}

