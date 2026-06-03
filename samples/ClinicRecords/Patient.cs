namespace ClinicRecords;

/// <summary>
/// A patient record holding a realistic mix of non-sensitive and highly sensitive fields.
/// The sensitive fields are encrypted at rest; the rest are stored in the clear so they
/// remain queryable.
/// </summary>
public sealed class Patient
{
    public int Id { get; set; }

    /// <summary>Display name — not encrypted (often needed for sorting/searching).</summary>
    public string FullName { get; set; } = "";

    /// <summary>Non-identifying clinic the patient is registered with — not encrypted.</summary>
    public string Clinic { get; set; } = "";

    /// <summary>Contact email — encrypted (PII).</summary>
    public string Email { get; set; } = "";

    /// <summary>National identifier / SSN — encrypted (sensitive PII).</summary>
    public string NationalId { get; set; } = "";

    /// <summary>Free-text clinical diagnosis — encrypted (sensitive medical data).</summary>
    public string? Diagnosis { get; set; }

    /// <summary>Last four digits of a card on file — encrypted (financial data).</summary>
    public string? CardLast4 { get; set; }
}
