# Releasing scanssh

## Step 1: Update the version number

Edit `configure.ac` and update the version in the `AC_INIT` line:

```
AC_INIT([scanssh],[X.Y.Z],[https://github.com/ofalk/scanssh/issues])
```

## Step 2: Regenerate autoconf files

```
autoreconf
```

This regenerates `configure`, `config.h.in`, and other auto-generated files.

## Step 3: Build and test

```
./configure
make
```

Run the binary to verify it works:

```
./scanssh -V
```

## Step 4: Create the distribution tarball

```
make dist
```

This creates `scanssh-X.Y.Z.tar.gz`.

## Step 5: Tag the release

```
git add -A
git commit -m "Release X.Y.Z"
git tag -a X.Y.Z -m "Release X.Y.Z"
git push origin master
git push origin X.Y.Z
```

## Optional: Test the tarball

```
tar xzf scanssh-X.Y.Z.tar.gz
cd scanssh-X.Y.Z
./configure
make
```
