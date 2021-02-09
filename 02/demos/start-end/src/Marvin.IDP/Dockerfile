FROM mcr.microsoft.com/dotnet/sdk:3.1 AS build
WORKDIR /src

# Copy csproj and restore as distinct layers

COPY *.csproj ./
RUN dotnet restore

# Copy everything else and build

COPY . ./
WORKDIR /src/.
RUN dotnet build -c Release -o /app/build

# publish

FROM build AS publish
RUN dotnet publish -c Release -o /app/publish

# Build runtime image

FROM mcr.microsoft.com/dotnet/aspnet:3.1
#FROM baseaspcore
WORKDIR /app
EXPOSE 44318
ENV ASPNETCORE_URLS=https://*:44318
ENV ASPNETCORE_Kestrel__Certificates__Default__Password=password
ENV ASPNETCORE_Kestrel__Certificates__Default__Path=/live/certificate.pfx
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Marvin.IDP.dll"]
