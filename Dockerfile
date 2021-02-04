#some info
#about sln in docker https://stackoverflow.com/questions/56150932/docker-file-skipping-project-because-it-was-not-found
# https://stackoverflow.com/questions/47103570/asp-net-core-2-0-multiple-projects-solution-docker-file
#https://github.com/dotnet/dotnet-docker/tree/master/samples/dotnetapp
#https://docs.docker.com/engine/examples/dotnetcore/

#https://github.com/dotnet/dotnet-docker/issues/1649
#https://github.com/dotnet/dotnet-docker/issues/1309



# https://hub.docker.com/_/microsoft-dotnet
FROM mcr.microsoft.com/dotnet/sdk:3.1 AS build
WORKDIR /app

# copy csproj and restore as distinct layers
COPY *.sln ./
COPY ["jwtLib/jwtLib.csproj", "jwtLib/"]
COPY ["jwtLibUsage/jwtLibUsage.csproj", "jwtLibUsage/"]
#COPY jwtLibUsage/jwtLibUsage.csproj ./jwtLibUsage
#COPY  ["jwtLib/jwtLib.csproj", "."]
RUN dotnet restore

# copy and publish app and libraries
COPY . ./
#COPY ["jwtLib", "./"]
#что бы не запускать тут билд отдельной командой, надо добавить игнор на все bin obj папки и другой мусор
#RUN dotnet build  -o /app/out
RUN dotnet publish -c release -o /app/out --no-restore

# final stage/image
FROM mcr.microsoft.com/dotnet/runtime:3.1
WORKDIR /app
COPY --from=build /app/out .
ENTRYPOINT ["dotnet", "jwtLibUsage.dll"]