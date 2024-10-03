using identity_trial3.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Text;
using identity_trial3.Services;
using Microsoft.AspNetCore.Identity.UI.Services;
var builder = WebApplication.CreateBuilder(args);
var jwtKey = builder.Configuration["jwt:SecretKey"];
var jwt = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey ?? throw new ArgumentNullException(jwtKey, "Token no configurado")));


// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddScoped<IEmailSender, EmailSender>();

builder.Services.AddDbContext<DataContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));


builder.Services.AddAuthorization();
builder.Services.AddAuthentication(options => {

    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

}).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = jwt,
        ValidateLifetime = true,
        ValidIssuer = "Aprende_Mas",
        ValidAudience = "Aprende_Mas",
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<DataContext>()
    .AddDefaultTokenProviders();

builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromMinutes(30);
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
