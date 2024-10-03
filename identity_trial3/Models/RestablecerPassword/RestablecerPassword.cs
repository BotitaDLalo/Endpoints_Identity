using System.ComponentModel.DataAnnotations;

namespace identity_trial3.Models.RestablecerPassword
{
    public class RestablecerPassword
    {
        public string Token { get; set; }

        public string Email { get; set; }

        [Required(ErrorMessage = "Es necesario confirmar la contraseña")]
        [DataType(DataType.Password)]
        public string NuevaPassword { get; set; }

        [Required(ErrorMessage = "Es necesario confirmar la contraseña")]
        [DataType(DataType.Password)]
        [Compare("NuevaPassword", ErrorMessage = "Las contraseñas no coinciden.")]
        public string ConfirmarPassword { get; set; }
    }
}
