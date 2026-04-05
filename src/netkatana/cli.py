import asyncio


async def hello() -> None:
    print("Hello...")
    await asyncio.sleep(1)
    print("World!")


def main() -> None:
    asyncio.run(hello())


if __name__ == "__main__":
    main()
